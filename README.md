# vault

**vault** is a simple, secure command-line password manager written in C++. It stores encrypted credentials in a vault file and opens a plaintext editor (e.g., nano) for editing entries temporarily.

## Usage

`./vault.exe [--filepath <file>] [--change_pass]`

### Examples
`./vault.exe`                   # Uses vault.dat or $VAULT_FILE

`./vault.exe myvault.dat`       # Use custom vault file

`./vault.exe --change_pass`     # Change passphrase

`./vault.exe --filepath myvault.dat --change_pass` 

## Requirements

- C++17 compatible compiler (tested with `g++`)
- OpenSSL development libraries
- `nano` installed (on Windows, use Git Bash or Cmder)

## Build

```bash
mingw32-make         # On Windows with MSYS2
```

## Environment Variables
`VAULT_FILE`: If set, used as the default vault file unless overridden on the command line.

## Security Notes

- The editor temporarily saves plaintext to a file in the system's temp directory.

- The temporary file is securely deleted after editing.

- Make sure you're using a secure terminal (e.g., not logging commands or displaying history)