//! Optional WatchKey Companion integration.
//!
//! Enabling creates a second master-key wrap protected by Windows DPAPI for the
//! current user. This is intentionally weaker than the original Windows
//! Hello-bound wrap. Enrollment alone does not create it, and disabling removes
//! it again.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::OsRng;
use p256::{EncodedPoint, PublicKey};
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Security::Cryptography::DataProtection::DataProtectionProvider;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::Authentication::Identity::{GetUserNameExW, NameSamCompatible};
use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT};
use zeroize::Zeroize;

use crate::error::WatchkeyError;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAXIMUM_RESPONSE_BYTES: u64 = 1_048_576;
const MAXIMUM_PROMPT_DURATION: Duration = Duration::from_secs(125);

#[derive(Debug, Serialize, Deserialize)]
struct CompanionConfig {
    base_url: String,
    machine_id: String,
    agent_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protected_master_key: Option<String>,
    #[serde(default)]
    enabled: bool,
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    code: &'a str,
    name: &'a str,
    os: &'static str,
    #[serde(rename = "agentVersion")]
    agent_version: &'static str,
}

#[derive(Deserialize)]
struct EnrollResponse {
    #[serde(rename = "machineId")]
    machine_id: String,
    #[serde(rename = "agentToken")]
    agent_token: String,
}

#[derive(Serialize)]
struct PromptRequest<'a> {
    operation: &'a str,
    service: &'a str,
    command: &'a str,
    #[serde(rename = "workingDirectory")]
    working_directory: Option<&'a str>,
    requester: &'a str,
    #[serde(rename = "agentPublicKey")]
    agent_public_key: &'a str,
}

#[derive(Deserialize)]
struct PromptCreated {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}

#[derive(Deserialize)]
struct PromptResult {
    status: String,
    mode: Option<String>,
    #[serde(rename = "browserPublicKey")]
    browser_public_key: Option<String>,
    ciphertext: Option<String>,
    iv: Option<String>,
}

#[derive(Deserialize, Zeroize)]
struct PasswordEnvelope {
    password: String,
}

enum RemoteError {
    Denied,
    InvalidPassword,
    Unavailable(String),
}

/// Pair this machine while retaining the original Windows Hello-only key wrap.
pub fn enroll(base_url: &str, code: &str) -> Result<(), WatchkeyError> {
    let base_url = validate_base_url(base_url)?;
    let machine_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".into());
    let response = send_json(
        build_client()?
            .post(endpoint(&base_url, "api/agent/enroll")?)
            .json(&EnrollRequest {
                code,
                name: &machine_name,
                os: "windows",
                agent_version: AGENT_VERSION,
            })
            .send()
            .map_err(companion_error)?
            .error_for_status()
            .map_err(companion_error)?,
    )?;

    let response: EnrollResponse = response;
    if !valid_identifier(&response.machine_id, "machine_")
        || response.agent_token.len() < 32
        || response.agent_token.len() > 512
        || !response
            .agent_token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(companion_error(
            "the server returned invalid machine credentials",
        ));
    }

    save_config(&CompanionConfig {
        base_url: base_url.as_str().trim_end_matches('/').to_string(),
        machine_id: response.machine_id,
        agent_token: response.agent_token,
        protected_master_key: None,
        enabled: false,
    })
}

/// Create the explicit DPAPI alternate wrap and enable remote prompts.
///
/// The caller must obtain `master_key` through Windows Hello immediately
/// before calling this function.
pub fn enable(master_key: &[u8; 32]) -> Result<(), WatchkeyError> {
    let mut config = load_config()?;
    validate_config(&config)?;
    config.protected_master_key = Some(protect_for_current_user(master_key)?);
    config.enabled = true;
    save_config(&config)
}

/// Disable remote prompts and delete the DPAPI alternate master-key wrap.
pub fn disable() -> Result<(), WatchkeyError> {
    let mut config = load_config()?;
    validate_config(&config)?;
    config.enabled = false;
    config.protected_master_key = None;
    save_config(&config)
}

pub fn unpair() -> Result<(), WatchkeyError> {
    remove_config_files(true)
}

/// Remove the local alternate key wrap when WatchKey's secret store is reset.
pub fn reset() -> Result<(), WatchkeyError> {
    remove_config_files(false)
}

/// Request remote approval and return the Companion-wrapped master key.
///
/// `Ok(None)` means Companion is disabled, not configured, or unavailable and
/// the caller should use Windows Hello. Explicit denial and an invalid submitted
/// password are terminal and never silently fall back.
pub fn request_master_key(
    operation: &str,
    service: &str,
    explicit_command: Option<&str>,
) -> Result<Option<[u8; 32]>, WatchkeyError> {
    let path = match config_path() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("watchkey companion unavailable: {error}");
            return Ok(None);
        }
    };
    if !path.exists() {
        return Ok(None);
    }
    let config = match load_config() {
        Ok(config) if config.enabled => config,
        Ok(_) => return Ok(None),
        Err(error) => {
            eprintln!("watchkey companion unavailable: {error}");
            return Ok(None);
        }
    };

    match request_master_key_inner(&config, operation, service, explicit_command) {
        Ok(result) => Ok(result),
        Err(RemoteError::Denied) => Err(WatchkeyError::RemoteApprovalDenied),
        Err(RemoteError::InvalidPassword) => Err(WatchkeyError::AuthenticationFailed(
            "The submitted Windows account password was not valid.".into(),
        )),
        Err(RemoteError::Unavailable(message)) => {
            eprintln!("watchkey companion unavailable: {message}");
            Ok(None)
        }
    }
}

fn request_master_key_inner(
    config: &CompanionConfig,
    operation: &str,
    service: &str,
    explicit_command: Option<&str>,
) -> Result<Option<[u8; 32]>, RemoteError> {
    validate_config(config).map_err(remote_error)?;
    let base_url = validate_base_url(&config.base_url).map_err(remote_error)?;
    let invocation = std::env::args()
        .map(|argument| shell_quote(&argument))
        .collect::<Vec<_>>()
        .join(" ");
    let captured = std::env::var("WATCHKEY_FULL_COMMAND")
        .ok()
        .filter(|value| !value.is_empty());
    let command = command_context(&invocation, explicit_command, captured.as_deref());
    let command = truncate(&command, 8_192);
    let working_directory = std::env::current_dir()
        .ok()
        .and_then(|path| path.to_str().map(|value| truncate(value, 2_048)));
    let requester = truncate(
        &std::env::var("USERNAME").unwrap_or_else(|_| "current user".into()),
        256,
    );
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let public_key = EncodedPoint::from(ephemeral_secret.public_key());
    let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key.as_bytes());
    let client = build_client().map_err(remote_error)?;

    let created: PromptCreated = send_json_remote(
        client
            .post(endpoint(&base_url, "api/agent/requests").map_err(remote_error)?)
            .bearer_auth(&config.agent_token)
            .header("x-watchkey-machine-id", &config.machine_id)
            .json(&PromptRequest {
                operation,
                service,
                command: &command,
                working_directory: working_directory.as_deref(),
                requester: &requester,
                agent_public_key: &public_key_b64,
            })
            .send()
            .map_err(remote_error)?
            .error_for_status()
            .map_err(remote_error)?,
    )?;
    if !valid_identifier(&created.request_id, "req_") {
        return Err(remote_error("the server returned an invalid request ID"));
    }

    let now = unix_millis();
    let server_wait = Duration::from_millis(created.expires_at.saturating_sub(now));
    let deadline = Instant::now() + server_wait.min(MAXIMUM_PROMPT_DURATION);

    while Instant::now() < deadline {
        let result: PromptResult = send_json_remote(
            client
                .get(
                    endpoint(
                        &base_url,
                        &format!("api/agent/requests/{}", created.request_id),
                    )
                    .map_err(remote_error)?,
                )
                .bearer_auth(&config.agent_token)
                .header("x-watchkey-machine-id", &config.machine_id)
                .send()
                .map_err(remote_error)?
                .error_for_status()
                .map_err(remote_error)?,
        )?;

        match (result.status.as_str(), result.mode.as_deref()) {
            ("approved", Some("passwordless")) => {
                return unprotect_master_key(
                    config
                        .protected_master_key
                        .as_deref()
                        .ok_or_else(|| remote_error("missing alternate master-key wrap"))?,
                )
                .map(Some)
                .map_err(remote_error);
            }
            ("approved", Some("password")) => {
                let mut envelope = decrypt_password(&created.request_id, ephemeral_secret, result)?;
                let verified = verify_local_password(&mut envelope.password);
                envelope.zeroize();
                if !verified {
                    return Err(RemoteError::InvalidPassword);
                }
                return unprotect_master_key(
                    config
                        .protected_master_key
                        .as_deref()
                        .ok_or_else(|| remote_error("missing alternate master-key wrap"))?,
                )
                .map(Some)
                .map_err(remote_error);
            }
            ("denied" | "expired", _) => return Err(RemoteError::Denied),
            ("pending", _) => thread::sleep(Duration::from_millis(800)),
            _ => return Err(remote_error("the server returned an invalid prompt status")),
        }
    }
    Err(RemoteError::Denied)
}

fn decrypt_password(
    request_id: &str,
    secret: EphemeralSecret,
    result: PromptResult,
) -> Result<PasswordEnvelope, RemoteError> {
    let peer_bytes = URL_SAFE_NO_PAD
        .decode(
            result
                .browser_public_key
                .ok_or_else(|| remote_error("missing browser public key"))?,
        )
        .map_err(remote_error)?;
    if peer_bytes.len() != 65 {
        return Err(remote_error("invalid browser public key"));
    }
    let peer = PublicKey::from_sec1_bytes(&peer_bytes).map_err(remote_error)?;
    let shared = secret.diffie_hellman(&peer);
    let cipher = Aes256Gcm::new_from_slice(shared.raw_secret_bytes())
        .map_err(|_| remote_error("invalid shared secret"))?;
    let iv = URL_SAFE_NO_PAD
        .decode(
            result
                .iv
                .ok_or_else(|| remote_error("missing encryption nonce"))?,
        )
        .map_err(remote_error)?;
    if iv.len() != 12 {
        return Err(remote_error("invalid encryption nonce"));
    }
    let nonce_bytes: [u8; 12] = iv
        .as_slice()
        .try_into()
        .map_err(|_| remote_error("invalid encryption nonce"))?;
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = URL_SAFE_NO_PAD
        .decode(
            result
                .ciphertext
                .ok_or_else(|| remote_error("missing encrypted password"))?,
        )
        .map_err(remote_error)?;
    if ciphertext.len() < 16 || ciphertext.len() > 8_192 {
        return Err(remote_error("invalid encrypted password"));
    }
    let mut plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: request_id.as_bytes(),
            },
        )
        .map_err(|_| remote_error("password decryption failed"))?;
    let result = serde_json::from_slice(&plaintext).map_err(remote_error);
    plaintext.zeroize();
    result
}

fn verify_local_password(password: &mut String) -> bool {
    let Some((domain, username)) = current_account() else {
        password.zeroize();
        return false;
    };
    let username_wide = wide(&username);
    let domain_wide = wide(&domain);
    let domain_pointer = if domain.is_empty() {
        PCWSTR::null()
    } else {
        PCWSTR(domain_wide.as_ptr())
    };
    let mut password_wide = wide(password);
    let mut token = windows::Win32::Foundation::HANDLE::default();
    let result = unsafe {
        LogonUserW(
            PCWSTR(username_wide.as_ptr()),
            domain_pointer,
            PCWSTR(password_wide.as_ptr()),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    password_wide.zeroize();
    password.zeroize();
    if result.is_ok() {
        unsafe {
            let _ = CloseHandle(token);
        }
        true
    } else {
        false
    }
}

fn current_account() -> Option<(String, String)> {
    let mut length = 0_u32;
    unsafe {
        let _ = GetUserNameExW(NameSamCompatible, PWSTR::null(), &mut length);
    }
    if length <= 1 || length > 32_768 {
        return None;
    }
    let mut buffer = vec![0_u16; length as usize];
    if !unsafe { GetUserNameExW(NameSamCompatible, PWSTR(buffer.as_mut_ptr()), &mut length) }
        .as_bool()
    {
        return None;
    }
    let terminator = buffer.iter().position(|value| *value == 0)?;
    let account = String::from_utf16(&buffer[..terminator]).ok()?;
    let (domain, username) = account.split_once('\\')?;
    if domain.is_empty() || username.is_empty() {
        return None;
    }
    Some((domain.to_owned(), username.to_owned()))
}

fn protect_for_current_user(value: &[u8]) -> Result<String, WatchkeyError> {
    let provider = DataProtectionProvider::CreateOverloadExplicit(&HSTRING::from("LOCAL=user"))?;
    let input = CryptographicBuffer::CreateFromByteArray(value)?;
    let output = provider.ProtectAsync(&input)?.get()?;
    let mut bytes = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&output, &mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}

fn unprotect_master_key(value: &str) -> Result<[u8; 32], WatchkeyError> {
    let protected = URL_SAFE_NO_PAD.decode(value).map_err(companion_error)?;
    let provider = DataProtectionProvider::new()?;
    let input = CryptographicBuffer::CreateFromByteArray(&protected)?;
    let output = provider.UnprotectAsync(&input)?.get()?;
    let mut bytes = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&output, &mut bytes)?;
    if bytes.len() != 32 {
        return Err(WatchkeyError::MasterKeyCorrupted);
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(bytes.as_ref());
    Ok(key)
}

fn validate_base_url(value: &str) -> Result<Url, WatchkeyError> {
    let mut url = Url::parse(value).map_err(companion_error)?;
    let host = url
        .host_str()
        .ok_or_else(|| companion_error("the Companion URL must include a host"))?
        .to_ascii_lowercase();
    let allowed_scheme = url.scheme() == "https"
        || (url.scheme() == "http" && matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"));
    if !allowed_scheme
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(companion_error(
            "use an HTTPS origin (HTTP is allowed only for localhost)",
        ));
    }
    url.set_path("/");
    Ok(url)
}

fn validate_config(config: &CompanionConfig) -> Result<(), WatchkeyError> {
    validate_base_url(&config.base_url)?;
    if !valid_identifier(&config.machine_id, "machine_")
        || config.agent_token.len() < 32
        || config.agent_token.len() > 512
        || !config
            .agent_token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(companion_error(
            "the local Companion configuration is invalid",
        ));
    }
    if let Some(protected_master_key) = &config.protected_master_key {
        if protected_master_key.len() < 16
            || protected_master_key.len() > 16_384
            || !protected_master_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(companion_error(
                "the local Companion master-key wrap is invalid",
            ));
        }
    } else if config.enabled {
        return Err(companion_error(
            "the enabled Companion pairing has no alternate master-key wrap",
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() >= prefix.len() + 16
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn endpoint(base_url: &Url, path: &str) -> Result<Url, WatchkeyError> {
    base_url.join(path).map_err(companion_error)
}

fn build_client() -> Result<Client, WatchkeyError> {
    Client::builder()
        // Companion origins are explicitly configured and validated. Bypassing
        // ambient proxy settings keeps loopback-only HTTP traffic on loopback
        // and avoids disclosing pairing or machine credentials to a proxy.
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .redirect(Policy::none())
        .build()
        .map_err(companion_error)
}

fn send_json<T: DeserializeOwned>(response: Response) -> Result<T, WatchkeyError> {
    if response.content_length().unwrap_or(0) > MAXIMUM_RESPONSE_BYTES {
        return Err(companion_error("the Companion response was too large"));
    }
    let mut bytes = Vec::new();
    response
        .take(MAXIMUM_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(companion_error)?;
    if bytes.len() as u64 > MAXIMUM_RESPONSE_BYTES {
        return Err(companion_error("the Companion response was too large"));
    }
    serde_json::from_slice(&bytes).map_err(WatchkeyError::from)
}

fn send_json_remote<T: DeserializeOwned>(response: Response) -> Result<T, RemoteError> {
    send_json(response).map_err(remote_error)
}

fn config_path() -> Result<PathBuf, WatchkeyError> {
    config_path_from(dirs::data_local_dir())
}

fn config_path_from(data_local_dir: Option<PathBuf>) -> Result<PathBuf, WatchkeyError> {
    let directory = data_local_dir.ok_or_else(|| {
        WatchkeyError::StorageIo(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Windows LocalAppData directory is unavailable",
        ))
    })?;
    Ok(directory.join("watchkey").join("companion.json"))
}

fn temporary_config_path(path: &Path) -> PathBuf {
    path.with_extension("json.tmp")
}

fn remove_config_files(require_existing: bool) -> Result<(), WatchkeyError> {
    let path = config_path()?;
    remove_config_files_at(&path, require_existing)
}

fn remove_config_files_at(path: &Path, require_existing: bool) -> Result<(), WatchkeyError> {
    let temporary = temporary_config_path(path);
    let mut found = false;
    let mut first_error = None;
    for candidate in [path, temporary.as_path()] {
        match fs::remove_file(candidate) {
            Ok(()) => found = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    if let Some(error) = first_error {
        return Err(error.into());
    }
    if require_existing && !found {
        return Err(WatchkeyError::InvalidArgument(
            "This PC is not paired with a Companion server.".into(),
        ));
    }
    Ok(())
}

fn save_config(config: &CompanionConfig) -> Result<(), WatchkeyError> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(config)?;
    let temporary = temporary_config_path(&path);
    if let Err(error) = fs::write(&temporary, data) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(temporary);
        return Err(error.into());
    }
    Ok(())
}

fn load_config() -> Result<CompanionConfig, WatchkeyError> {
    let config = serde_json::from_slice(&fs::read(config_path()?)?)?;
    Ok(config)
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "_./:=+-".contains(character))
    {
        value.to_string()
    } else {
        format!("\"{}\"", value.replace('"', "\\\""))
    }
}

fn json_quote(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"<unavailable>\"".into())
}

fn command_context(
    invocation: &str,
    explicit_command: Option<&str>,
    captured_outer_command: Option<&str>,
) -> String {
    let invocation_context = format!("WatchKey invocation: {invocation}");
    if let Some(explicit_command) = explicit_command.filter(|value| !value.is_empty()) {
        format!(
            "{invocation_context}; integration-reported outer command (unverified): {}",
            json_quote(explicit_command)
        )
    } else if let Some(captured) = captured_outer_command.filter(|value| !value.is_empty()) {
        format!(
            "{invocation_context}; caller-reported outer command (unverified): {}",
            json_quote(captured)
        )
    } else {
        invocation_context
    }
}

fn truncate(value: &str, length: usize) -> String {
    value.chars().take(length).collect()
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn remote_error(error: impl std::fmt::Display) -> RemoteError {
    RemoteError::Unavailable(error.to_string())
}

fn companion_error(error: impl std::fmt::Display) -> WatchkeyError {
    WatchkeyError::AuthenticationFailed(format!("Companion: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_local_app_data_fails_closed() {
        assert!(config_path_from(None).is_err());
    }

    #[test]
    fn lifecycle_cleanup_removes_primary_and_temporary_config() {
        let directory = std::env::temp_dir().join(format!(
            "watchkey-companion-cleanup-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("companion.json");
        let temporary = temporary_config_path(&path);
        fs::write(&path, b"primary").unwrap();
        fs::write(&temporary, b"protected_master_key").unwrap();

        remove_config_files_at(&path, true).unwrap();

        assert!(!path.exists());
        assert!(!temporary.exists());
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn command_context_keeps_actual_invocation_and_labels_outer_command() {
        let command = command_context(
            "watchkey get PRODUCTION_TOKEN",
            None,
            Some("npm run harmless-preview"),
        );

        assert!(command.starts_with("WatchKey invocation: watchkey get PRODUCTION_TOKEN"));
        assert!(command.contains("caller-reported outer command (unverified)"));
        assert!(command.contains("\"npm run harmless-preview\""));
    }
}
