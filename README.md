# LTO-Encryption-Manager
**LTO-Encryption-Manager** provides LTO tape AES key management on Windows using SLIP-0021 symmetric key derivation from a BIP-0039 wallet seed phrase.

LTO-Encryption-Manager is part of the [**Data Backups and Archiving GitHub Project**](https://github.com/users/watfordjc/projects/2).

## Pre-Release Builds

The application currently (commit 4e5ed52b) requires elevated privileges to run. I do not recall if that is to check TPM and/or Secure Boot state, to get tape drive information using CIM, or to communicate with tape drives using SPTI.

TPM 2.0 and Secure Boot are currently (commit 4e5ed52b) required as account derivation keys are encrypted using a TPM-backed RSA certificate created for your Windows user account.

Caution: Make sure you create a pencil and paper backup of your BIP-0039 seed phrase(s). Updating your motherboard UEFI firmware and/or changing UEFI settings such as whether dTPM/fTPM is used/enabled/disabled or if Secure Boot is enabled/disabled or whether CSM support is enabled, may result in your user's RSA private key created for use with LTO-Encryption-Manager no longer being available. Reversing your changes may or may not restore access to the key.

Encrypted account keys are stored in ```%LocalAppData%\John Cook UK\LTO-Encryption-Manager\Accounts\```.

## Additional Information

LTO-Encryption-Manager implements the key derivation scheme discussed in [backup-policy/wiki/LTO-Encryption-Keys](https://github.com/watfordjc/backup-policy/wiki/LTO-Encryption-Keys).

This repository is a work in progress.
