use sha2::{Digest, Sha256};
use windows::Security::Credentials::{
    KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;

use crate::error::WatchkeyError;

const CREDENTIAL_NAME: &str = "watchkey";

/// Fixed challenge used for all authentication requests.
/// The signature of this challenge is used to derive the wrapping key.
fn fixed_challenge() -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"watchkey-auth-challenge-v1");
    hasher.finalize().to_vec()
}

fn bytes_to_buffer(data: &[u8]) -> windows::core::Result<IBuffer> {
    CryptographicBuffer::CreateFromByteArray(data)
}

fn buffer_to_bytes(buffer: &IBuffer) -> windows::core::Result<Vec<u8>> {
    let mut bytes = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buffer, &mut bytes)?;
    Ok(bytes.as_ref().to_vec())
}

/// Check if Windows Hello is available and configured.
pub fn check_support() -> Result<(), WatchkeyError> {
    let supported = KeyCredentialManager::IsSupportedAsync()?.get()?;
    if !supported {
        return Err(WatchkeyError::WindowsHelloNotSupported);
    }
    Ok(())
}

/// Ensure a Windows Hello credential exists for watchkey.
/// Creates one on first use (which triggers a biometric/PIN prompt).
pub fn ensure_credential() -> Result<(), WatchkeyError> {
    // Try to open an existing credential first.
    let result = KeyCredentialManager::OpenAsync(&CREDENTIAL_NAME.into())?.get()?;

    if result.Status()? == KeyCredentialStatus::NotFound {
        // Create a new credential — triggers Windows Hello enrollment prompt.
        let create_result = KeyCredentialManager::RequestCreateAsync(
            &CREDENTIAL_NAME.into(),
            KeyCredentialCreationOption::FailIfExists,
        )?
        .get()?;

        match create_result.Status()? {
            KeyCredentialStatus::Success => {}
            KeyCredentialStatus::CredentialAlreadyExists => {
                // Race condition — another process created it. That's fine.
            }
            KeyCredentialStatus::UserCanceled => {
                return Err(WatchkeyError::AuthenticationCancelled);
            }
            status => {
                return Err(WatchkeyError::CredentialCreateFailed(format!(
                    "status: {status:?}"
                )));
            }
        }
    }

    Ok(())
}

/// Authenticate via Windows Hello and return the raw signature bytes.
/// This triggers a biometric/PIN prompt every time.
pub fn authenticate() -> Result<Vec<u8>, WatchkeyError> {
    let challenge = fixed_challenge();
    let challenge_buffer = bytes_to_buffer(&challenge)?;

    let open_result = KeyCredentialManager::OpenAsync(&CREDENTIAL_NAME.into())?.get()?;

    if open_result.Status()? == KeyCredentialStatus::NotFound {
        return Err(WatchkeyError::MasterKeyCorrupted);
    }

    let credential = open_result
        .Credential()
        .map_err(|e| WatchkeyError::AuthenticationFailed(e.message().to_string()))?;

    let sign_result = credential.RequestSignAsync(&challenge_buffer)?.get()?;

    match sign_result.Status()? {
        KeyCredentialStatus::Success => {
            let result_buffer = sign_result.Result()?;
            let signature = buffer_to_bytes(&result_buffer)?;
            Ok(signature)
        }
        KeyCredentialStatus::UserCanceled => Err(WatchkeyError::AuthenticationCancelled),
        status => Err(WatchkeyError::AuthenticationFailed(format!(
            "status: {status:?}"
        ))),
    }
}

/// Compute the SHA-256 hash of a signature (for determinism checking).
pub fn signature_hash(signature: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(signature);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
