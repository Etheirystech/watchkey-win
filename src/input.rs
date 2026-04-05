use std::io::{self, IsTerminal, Read};

use crate::error::WatchkeyError;

/// Prompt for a service name if one wasn't provided on the command line.
pub fn prompt_service(service: &str) -> Result<String, WatchkeyError> {
    if !service.is_empty() {
        return Ok(service.to_string());
    }

    eprint!("Key name: ");
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| WatchkeyError::InvalidArgument(e.to_string()))?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(WatchkeyError::InvalidArgument(
            "No key name provided".to_string(),
        ));
    }

    Ok(trimmed)
}

/// Read a secret value from stdin.
/// If stdin is a TTY, prompts and suppresses echo.
/// If stdin is piped, reads all data.
pub fn read_secret() -> Result<String, WatchkeyError> {
    if io::stdin().is_terminal() {
        eprint!("Enter value: ");
        let value = rpassword::read_password()
            .map_err(|e| WatchkeyError::InvalidArgument(e.to_string()))?;
        if value.is_empty() {
            return Err(WatchkeyError::InvalidArgument(
                "No value provided".to_string(),
            ));
        }
        Ok(value)
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| WatchkeyError::InvalidArgument(e.to_string()))?;
        let value = buf.trim_end_matches('\n').trim_end_matches('\r');
        if value.is_empty() {
            return Err(WatchkeyError::InvalidArgument(
                "No value provided on stdin".to_string(),
            ));
        }
        Ok(value.to_string())
    }
}
