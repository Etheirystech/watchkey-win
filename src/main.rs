mod auth;
mod cli;
mod companion;
mod crypto;
mod error;
mod input;
mod storage;

use error::WatchkeyError;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

fn main() {
    let result = run();
    match result {
        Ok(()) => std::process::exit(0),
        Err(WatchkeyError::InvalidArgument(msg)) if msg.is_empty() => {
            // Already printed help/error — just exit.
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), WatchkeyError> {
    let cmd = cli::parse()?;
    match cmd {
        cli::Command::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        cli::Command::Help => {
            cli::print_help();
            Ok(())
        }
        cli::Command::List => cmd_list(),
        cli::Command::Get { service } => cmd_get(&service),
        cli::Command::Set { service } => cmd_set(&service),
        cli::Command::Delete { service } => cmd_delete(&service),
        cli::Command::Reset => cmd_reset(),
        cli::Command::CompanionEnroll { base_url, code } => cmd_companion_enroll(&base_url, &code),
        cli::Command::CompanionEnable => cmd_companion_enable(),
        cli::Command::CompanionDisable => cmd_companion_disable(),
        cli::Command::CompanionUnpair => cmd_companion_unpair(),
    }
}

// --- Master key management ---

/// Authenticate and obtain the master key for encrypting/decrypting secrets.
/// On first use, generates a new master key and wraps it with the Windows Hello signature.
/// On subsequent uses, unwraps the stored master key.
fn obtain_master_key(store: &mut storage::Store) -> Result<[u8; 32], WatchkeyError> {
    auth::check_support()?;
    auth::ensure_credential()?;
    let signature = Zeroizing::new(auth::authenticate()?);
    let wrapping_key = Zeroizing::new(crypto::derive_key(&signature));
    let sig_hash = auth::signature_hash(&signature);

    match &store.master_key {
        Some(encrypted_master_key) => {
            // Try to unwrap with the current signature's derived key.
            match crypto::decrypt(&wrapping_key, encrypted_master_key) {
                Ok(mut master_key_bytes) => {
                    let mut key = [0u8; 32];
                    if master_key_bytes.len() != 32 {
                        master_key_bytes.zeroize();
                        return Err(WatchkeyError::MasterKeyCorrupted);
                    }
                    key.copy_from_slice(&master_key_bytes);
                    master_key_bytes.zeroize();

                    // Update signature hash if it changed (deterministic re-wrap).
                    if store.signature_hash.as_deref() != Some(&sig_hash) {
                        store.signature_hash = Some(sig_hash);
                        storage::save(store)?;
                    }

                    Ok(key)
                }
                Err(_) => {
                    // Signature might be non-deterministic or Windows Hello was reset.
                    // Check if we have a previous signature hash to compare.
                    if store.signature_hash.is_some() {
                        // The signature changed — re-wrapping is impossible because
                        // we can't decrypt with the new key. The master key is lost.
                        Err(WatchkeyError::MasterKeyCorrupted)
                    } else {
                        Err(WatchkeyError::MasterKeyCorrupted)
                    }
                }
            }
        }
        None => {
            // First-time setup: generate a random master key and wrap it.
            let mut master_key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut master_key);

            let encrypted = crypto::encrypt(&wrapping_key, &master_key)?;
            store.master_key = Some(encrypted);
            store.signature_hash = Some(sig_hash);
            storage::save(store)?;

            Ok(master_key)
        }
    }
}

// --- Commands ---

fn cmd_list() -> Result<(), WatchkeyError> {
    let store = storage::load()?;
    for key in store.secrets.keys() {
        println!("{key}");
    }
    Ok(())
}

fn cmd_get(service: &str) -> Result<(), WatchkeyError> {
    let service = input::prompt_service(service)?;
    let mut store = storage::load()?;
    let master_key = Zeroizing::new(authorize_master_key(&mut store, "get", &service)?);

    let encrypted = store
        .secrets
        .get(&service)
        .ok_or_else(|| WatchkeyError::ServiceNotFound(service.clone()))?;

    let plaintext = crypto::decrypt(&master_key, encrypted)?;
    let value =
        String::from_utf8(plaintext).map_err(|e| WatchkeyError::CryptoError(e.to_string()))?;

    // No trailing newline — matches macOS behavior.
    print!("{value}");
    Ok(())
}

fn cmd_set(service: &str) -> Result<(), WatchkeyError> {
    let service = input::prompt_service(service)?;
    let mut store = storage::load()?;
    let master_key = Zeroizing::new(authorize_master_key(&mut store, "set", &service)?);
    let value = Zeroizing::new(input::read_secret()?);

    let encrypted = crypto::encrypt(&master_key, value.as_bytes())?;
    store.secrets.insert(service.clone(), encrypted);
    storage::save(&store)?;

    eprintln!("Stored \"{service}\" (auth required for access).");
    Ok(())
}

fn cmd_delete(service: &str) -> Result<(), WatchkeyError> {
    let service = input::prompt_service(service)?;
    let mut store = storage::load()?;
    let _master_key = Zeroizing::new(authorize_master_key(&mut store, "delete", &service)?);

    if store.secrets.remove(&service).is_none() {
        return Err(WatchkeyError::ServiceNotFound(service));
    }

    storage::save(&store)?;
    eprintln!("Deleted \"{service}\".");
    Ok(())
}

fn cmd_reset() -> Result<(), WatchkeyError> {
    companion::reset()?;
    storage::reset()?;
    eprintln!("All watchkey data has been removed.");
    Ok(())
}

fn authorize_master_key(
    store: &mut storage::Store,
    operation: &str,
    service: &str,
) -> Result<[u8; 32], WatchkeyError> {
    match companion::request_master_key(operation, service, None)? {
        Some(key) => Ok(key),
        None => obtain_master_key(store),
    }
}

fn cmd_companion_enroll(base_url: &str, code: &str) -> Result<(), WatchkeyError> {
    companion::enroll(base_url, code)?;
    eprintln!(
        "Paired this PC with {base_url}. Run `watchkey companion enable` to enable remote prompts."
    );
    Ok(())
}

fn cmd_companion_enable() -> Result<(), WatchkeyError> {
    let mut store = storage::load()?;
    let master_key = Zeroizing::new(obtain_master_key(&mut store)?);
    companion::enable(&master_key)?;
    eprintln!("Companion remote prompts enabled.");
    Ok(())
}

fn cmd_companion_disable() -> Result<(), WatchkeyError> {
    companion::disable()?;
    eprintln!(
        "Companion remote prompts disabled and its alternate master-key wrap was removed; Windows Hello will be used."
    );
    Ok(())
}

fn cmd_companion_unpair() -> Result<(), WatchkeyError> {
    companion::unpair()?;
    eprintln!("Removed the local Companion pairing.");
    Ok(())
}
