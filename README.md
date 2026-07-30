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

Requires [Rust](https://rustup.rs/) (`winget install Rustlang.Rustup`).

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
watchkey companion enroll <url> <code>
                                    Store a disabled Companion pairing
watchkey companion enable           Enable remote approval prompts
watchkey companion disable          Return to Windows Hello only
watchkey companion unpair           Remove the local Companion pairing
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

## Optional WatchKey Companion

[WatchKey Companion](https://github.com/Etheirystech/watchkey-companion) is an
optional, self-hosted web UI that can send browser push notifications and show
the machine, key name, working directory, and command requesting access.

Companion is off by default. Enrollment creates the local pairing but does not
activate remote prompts:

1. Sign in to your Companion web UI and select **Pair machine**.
2. Run the enrollment command shown by the web UI:

   ```powershell
   watchkey companion enroll https://watchkey.example.com ABCD-EFGH
   ```

3. Explicitly enable remote prompts. Windows Hello is required locally during
   this step, and only then is the alternate key wrap created:

   ```powershell
   watchkey companion enable
   ```

Use `watchkey companion disable` to immediately return to the original Windows
Hello-only protection while keeping the server pairing; disabling deletes the
alternate master-key wrap. Use `watchkey companion unpair` to remove the local
pairing, and revoke the machine in the Companion web UI if its token may have
been exposed. `watchkey reset` also removes the pairing and any alternate wrap.

When Companion is enabled, Windows Hello and the Companion request start
together. Approving either path is sufficient and closes the other prompt.
Cancelling Windows Hello denies and closes the pending Companion request before
the command exits. A remote denial or an invalid submitted Windows account
password is terminal. The password field expects the account password, not a
Windows Hello PIN. It is encrypted in the browser directly to an ephemeral key
created by this watchkey process, verified locally with `LogonUserW`, and is not
sent to the relay in plaintext.

Companion always shows the actual watchkey invocation. When
`WATCHKEY_FULL_COMMAND` is set, it also shows that value explicitly labeled as
a caller-reported, unverified outer command. Set the variable in a PowerShell
wrapper before calling watchkey when you want the exact outer command. Do not
put literal secrets on command lines because Companion displays and stores
command metadata.

Command context is advisory rather than OS-attested. Any program able to invoke
watchkey can also choose its environment and arguments, so always verify the
machine, operation, and key name shown by Companion.

### Windows security tradeoff

The original Windows Hello design requires a TPM-backed signature to unwrap
the secret-store master key. Remote approval cannot use that signature, so
enabling Companion creates an additional copy of the master key protected by
Windows DPAPI for the current Windows user. Enrollment by itself does not
create this copy.

This is a real reduction in protection: while Companion is enabled, code already running
as your Windows user may be able to use DPAPI to unwrap that copy without
Windows Hello or Companion. The Companion server's approval protects the
normal watchkey command path; it cannot prevent a malicious local process from
reading the pairing file and invoking DPAPI itself. Do not enroll Companion if
you require every master-key unwrap to remain cryptographically bound to
Windows Hello. `companion disable`, `companion unpair`, or `reset` removes the
DPAPI-wrapped copy.

TLS is required for non-localhost servers. End-to-end encryption keeps the
plaintext machine password out of relay storage, but a compromised self-hosted
server could serve modified browser JavaScript that captures it before
encryption.

## Security

- Secrets are stored encrypted at `%APPDATA%\watchkey\secrets.json`
- The encryption key never exists on disk — it's derived from a TPM-backed Windows Hello signature
- Resetting Windows Hello will invalidate all stored secrets (by design)
- `watchkey list` does not require authentication (only shows key names, not values)
- If Companion is enrolled, an additional DPAPI-wrapped master key is stored at
  `%LOCALAPPDATA%\watchkey\companion.json`; see the tradeoff above

## License

MIT
