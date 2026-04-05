# watchkey (Windows)

Access secrets with Windows Hello biometric authentication.

Windows equivalent of [watchkey](https://github.com/Etheirystech/watchkey) (macOS). Secrets are encrypted with AES-256-GCM using a key derived from Windows Hello authentication, ensuring biometric/PIN verification is required every time a secret is accessed.

## Requirements

- Windows 10 (21H2+) or Windows 11
- Windows Hello configured (fingerprint, face, or PIN)

## Installation

### Option 1: Download the binary

1. Download `watchkey.exe` from the [latest release](https://github.com/Etheirystech/watchkey-win/releases/latest)
2. Create a directory and move the binary there:

**PowerShell:**
```powershell
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\watchkey"
Move-Item watchkey.exe "$env:LOCALAPPDATA\watchkey\"
```

**Git Bash:**
```bash
mkdir -p "$LOCALAPPDATA/watchkey"
mv watchkey.exe "$LOCALAPPDATA/watchkey/"
```

3. Add to your PATH:

**PowerShell:**
```powershell
$path = [Environment]::GetEnvironmentVariable("Path", "User")
[Environment]::SetEnvironmentVariable("Path", "$path;$env:LOCALAPPDATA\watchkey", "User")
```

**Git Bash** (add to `~/.bashrc`):
```bash
export PATH="$LOCALAPPDATA/watchkey:$PATH"
```

4. Restart your terminal.

### Option 2: Build from source

Requires [Rust](https://rustup.rs/).

**PowerShell:**
```powershell
git clone https://github.com/Etheirystech/watchkey-win.git
cd watchkey-win
cargo build --release
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\watchkey"
Copy-Item target\release\watchkey.exe "$env:LOCALAPPDATA\watchkey\"
```

**Git Bash:**
```bash
git clone https://github.com/Etheirystech/watchkey-win.git
cd watchkey-win
cargo build --release
mkdir -p "$LOCALAPPDATA/watchkey"
cp target/release/watchkey.exe "$LOCALAPPDATA/watchkey/"
```

Then add to your PATH (see step 3 above) and restart your terminal.

## Usage

```
watchkey set <service>              Store a secret (reads from stdin)
watchkey get <service>              Retrieve a secret
watchkey delete <service>           Delete a stored secret
watchkey list                       List all stored keys
watchkey reset                      Remove all stored data
```

### PowerShell examples

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

### Git Bash examples

```bash
# Store a secret (will prompt for value and Windows Hello)
watchkey set DOPPLER_TOKEN_DEV

# Pipe a secret
echo "my-secret" | watchkey set API_KEY

# Retrieve a secret (triggers Windows Hello)
export DOPPLER_TOKEN="$(watchkey get DOPPLER_TOKEN_DEV)"

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
