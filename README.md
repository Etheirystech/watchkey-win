# watchkey (Windows)

Access secrets with Windows Hello biometric authentication.

Windows equivalent of [watchkey](https://github.com/Etheirystech/watchkey) (macOS). Secrets are encrypted with AES-256-GCM using a key derived from Windows Hello authentication, ensuring biometric/PIN verification is required every time a secret is accessed.

## Requirements

- Windows 10 (21H2+) or Windows 11
- Windows Hello configured (fingerprint, face, or PIN)

## Installation

Download the latest release from [GitHub Releases](https://github.com/Etheirystech/watchkey-win/releases) and add it to your PATH.

Or build from source:

```powershell
git clone https://github.com/Etheirystech/watchkey-win.git
cd watchkey-win
cargo build --release
copy target\release\watchkey.exe C:\Program Files\watchkey\
```

## Usage

```
watchkey set <service>              Store a secret (reads from stdin)
watchkey get <service>              Retrieve a secret
watchkey delete <service>           Delete a stored secret
watchkey list                       List all stored keys
watchkey reset                      Remove all stored data
```

### Examples

```powershell
# Store a secret (will prompt for value and Windows Hello)
watchkey set DOPPLER_TOKEN_DEV

# Pipe a secret
echo "my-secret" | watchkey set API_KEY

# Retrieve a secret (triggers Windows Hello)
$env:DOPPLER_TOKEN = $(watchkey get DOPPLER_TOKEN_DEV)

# List all stored keys
watchkey list

# Delete a secret
watchkey delete DOPPLER_TOKEN_DEV
```

## How it works

1. On first use, a Windows Hello-protected RSA key pair is created via `KeyCredentialManager`
2. A random 256-bit master key is generated and encrypted using a key derived from the Windows Hello signature
3. All secrets are encrypted with the master key using AES-256-GCM
4. Every `get`, `set`, or `delete` operation requires Windows Hello authentication to unwrap the master key

The biometric step is cryptographically bound — the master key cannot be decrypted without completing Windows Hello authentication, as the decryption key is derived from the TPM-backed signature.

## Security

- Secrets are stored encrypted at `%APPDATA%\watchkey\secrets.json`
- The encryption key never exists on disk — it's derived from a TPM-backed Windows Hello signature
- Resetting Windows Hello will invalidate all stored secrets (by design)
- `watchkey list` does not require authentication (only shows key names, not values)

## License

MIT
