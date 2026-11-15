# Security policy

## Reporting a vulnerability

Security issues are reported privately through the "Report a
vulnerability" function on the Security tab of the repository (GitHub
private vulnerability reporting). They must not be filed as public issues.

Reports must not contain passphrases, PINs, private keys, the output of
`kaltstart derive`, or a credential ID together with its salt.

## Supported versions

Only the current state of the `main` branch is supported; there is no
release yet.

## Scope

kaltstart is a proof of concept and has not been verified with a physical
token ([docs/verification.md](docs/verification.md)).

It protects the data of a disk or server that is lost, stolen or disposed
of: the passphrase is not stored on the disk and cannot be derived without
the token. It does not detect a server whose boot files were modified or
whose initramfs host key was copied; whoever controls such a server obtains
the passphrase that is submitted to it.

The threat model, the handling of secrets and the procedures for a lost
token or a compromise are described in
[docs/security.md](docs/security.md).
