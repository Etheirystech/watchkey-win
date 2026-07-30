use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};
use windows::core::s;
use windows::Foundation::IAsyncOperation;
use windows::Security::Credentials::{
    KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialOperationResult,
    KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_KEYBOARD, KEYEVENTF_KEYUP, VK_MENU,
};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowA, SetForegroundWindow, SetWindowPos, ShowWindow, HWND_TOPMOST, SWP_NOMOVE,
    SWP_NOSIZE, SW_SHOW,
};

use crate::error::WatchkeyError;

const CREDENTIAL_NAME: &str = "watchkey";

pub struct WindowsRuntimeGuard;

impl WindowsRuntimeGuard {
    pub fn initialize() -> Result<Self, WatchkeyError> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED)? };
        Ok(Self)
    }
}

impl Drop for WindowsRuntimeGuard {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

#[derive(Default)]
struct AuthenticationCancellationState {
    cancelled: bool,
    operation: Option<IAsyncOperation<KeyCredentialOperationResult>>,
}

/// Cancels an in-flight Windows Hello signing operation when Companion wins.
#[derive(Clone, Default)]
pub struct AuthenticationCancellation {
    state: Arc<Mutex<AuthenticationCancellationState>>,
}

impl AuthenticationCancellation {
    pub fn cancel(&self) {
        let operation = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.cancelled = true;
            state.operation.take()
        };
        if let Some(operation) = operation {
            let _ = operation.Cancel();
        }
    }

    fn register(&self, operation: &IAsyncOperation<KeyCredentialOperationResult>) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.cancelled {
            let _ = operation.Cancel();
            return false;
        }
        state.operation = Some(operation.clone());
        true
    }

    fn clear(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.operation = None;
    }

    fn is_cancelled(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .cancelled
    }
}

/// Spawn a background thread that polls for the Windows Security dialog
/// and brings it to the foreground using the ALT key trick.
/// Returns a guard that stops polling when dropped.
fn spawn_foreground_watcher() -> ForegroundGuard {
    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();

    thread::spawn(move || {
        let mut found = false;
        for _ in 0..100 {
            // Poll for up to 10 seconds (100 × 100ms)
            if done_clone.load(Ordering::Relaxed) {
                return;
            }

            unsafe {
                if let Ok(hwnd) = FindWindowA(s!("Credential Dialog Xaml Host"), None) {
                    if !found {
                        // First time seeing the dialog — use all tricks
                        // Simulate ALT key press/release to unlock SetForegroundWindow
                        let inputs = [
                            INPUT {
                                r#type: INPUT_KEYBOARD,
                                Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                                    ki: windows::Win32::UI::Input::KeyboardAndMouse::KEYBDINPUT {
                                        wVk: VK_MENU,
                                        ..Default::default()
                                    },
                                },
                            },
                            INPUT {
                                r#type: INPUT_KEYBOARD,
                                Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                                    ki: windows::Win32::UI::Input::KeyboardAndMouse::KEYBDINPUT {
                                        wVk: VK_MENU,
                                        dwFlags: KEYEVENTF_KEYUP,
                                        ..Default::default()
                                    },
                                },
                            },
                        ];
                        let _ = SendInput(&inputs, size_of::<INPUT>() as i32);
                        found = true;
                    }

                    // Force on top and to foreground — retry a few times
                    let _ = SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
                    let _ = ShowWindow(hwnd, SW_SHOW);
                    let _ = SetForegroundWindow(hwnd);

                    if found {
                        // Keep trying for a bit then stop
                        for _ in 0..5 {
                            thread::sleep(Duration::from_millis(50));
                            if done_clone.load(Ordering::Relaxed) {
                                return;
                            }
                            let _ = SetForegroundWindow(hwnd);
                        }
                        return;
                    }
                }
            }

            thread::sleep(Duration::from_millis(100));
        }
    });

    ForegroundGuard { done }
}

struct ForegroundGuard {
    done: Arc<AtomicBool>,
}

impl Drop for ForegroundGuard {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
    }
}

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
        let _guard = spawn_foreground_watcher();
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

/// Authenticate via Windows Hello while allowing a concurrent Companion
/// decision to dismiss the Windows Security dialog.
pub fn authenticate_with_cancellation(
    cancellation: &AuthenticationCancellation,
) -> Result<Vec<u8>, WatchkeyError> {
    let challenge = fixed_challenge();
    let challenge_buffer = bytes_to_buffer(&challenge)?;

    let open_result = KeyCredentialManager::OpenAsync(&CREDENTIAL_NAME.into())?.get()?;

    if open_result.Status()? == KeyCredentialStatus::NotFound {
        return Err(WatchkeyError::MasterKeyCorrupted);
    }

    let credential = open_result
        .Credential()
        .map_err(|e| WatchkeyError::AuthenticationFailed(e.message().to_string()))?;

    let _guard = spawn_foreground_watcher();
    let operation = credential.RequestSignAsync(&challenge_buffer)?;
    if !cancellation.register(&operation) {
        return Err(WatchkeyError::AuthenticationCancelled);
    }
    let sign_result = operation.get();
    cancellation.clear();
    if cancellation.is_cancelled() {
        return Err(WatchkeyError::AuthenticationCancelled);
    }
    let sign_result = sign_result?;

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
