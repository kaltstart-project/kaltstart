# Verification status

This document records what has been verified and what remains open. It is
updated whenever a check has been carried out.

## Summary

| Area | State |
|------|-------|
| Unit tests | A suite against stub executables and a model of the server side. The CI workflow runs it with Python 3.9 to 3.14; it was last run by hand with each of these versions on Linux. |
| Server side | Verified on Debian 13 with a stand-in program in place of the token. |
| Token side | Open. No physical token has been used. |

## Server-side verification

| Component | Version |
|-----------|---------|
| Distribution | Debian 13 with an encrypted root file system |
| dropbear-initramfs | 2025.89 |
| cryptsetup | 2.7.5 |
| OpenSSH client on the workstation | 10.0 |

The stand-in program took the place of `fido2-assert` and returned a fixed
value in the format of an `hmac-secret` output. Everything that follows the
derivation was exercised with the real components: ssh, dropbear,
`cryptroot-unlock`, cryptsetup and the boot process.

Verified:

- the typed fallback through the restricted SSH key with a terminal, also
  with comment lines in the `authorized_keys` file
- `unlock` through a jump host (`probe = no`), and directly with readiness
  check and start confirmation on a second address
- a rejected passphrase (exit status 5), three rejections in a row, and an
  initramfs port that cannot be reached (exit status 6)
- a host key that differs from the pinned one (exit status 4, nothing is
  sent, the server keeps waiting)
- three LUKS devices with `decrypt_keyctl`: one submission opens all of
  them
- three LUKS devices without a keyscript: with `prompts = 1` one device is
  opened and the server keeps waiting; with `prompts = 5` the remaining
  submissions follow and `unlock` stops as soon as no device is waiting or
  the initramfs no longer answers
- `enroll` as an unprivileged user with `admin_sudo = yes`: a device that
  is already enrolled (reported with its keyslot, nothing is written to the
  server); a new keyslot with the existing passphrase typed on the
  terminal (upload, comparison, verification, removal of the file); a new
  keyslot with `--existing-keyfile` (no file on the server); a device that
  is not a LUKS device (refused before the token is used)
- the removal of a passphrase with `cryptsetup luksRemoveKey --key-file -`
  as used in the rotation procedure, including its behavior with a
  passphrase in two keyslots and with empty input

The command lines for `fido2-assert`, `fido2-cred` and `fido2-token` follow
the manual pages of fido2-tools 1.15.0; they have not been run against a
device.

## Open checks

### Token

| Check | Expected result |
|-------|-----------------|
| `kaltstart init`, with and without `--no-pin` | A credential is created. Line 5 of the output of `fido2-cred` is the credential ID. |
| `init` and `derive` without `--device` | The only token is found in the output of `fido2-token -L`. |
| `kaltstart derive HOST`, repeated | The same 44 characters on every run. |
| `kaltstart derive HOST` with `pin = no`, for a credential created without `--no-pin` | The token refuses (exit status 3), or the value differs from the one derived with the PIN. An identical value means that the PIN does not protect the passphrase on this token. |
| Wrong token, missing touch, wrong PIN | Exit status 3. No SSH session is opened. |
| Complete cycle: `enroll`, reboot, `unlock` | The server starts. |
| Workstation running macOS | The device paths reported by `fido2-token -L` can be used. |

### Server

| Check | Expected result |
|-------|-----------------|
| Connection lost after the passphrase was delivered, against dropbear | Exit status 0 if the system starts. Covered so far by unit tests. |
| A correct passphrase that cryptsetup does not confirm within the ten seconds of `cryptroot-unlock` (many keyslots) | Exit status 0 if the system starts. Covered so far by unit tests. |
| `enroll` on a device that carries a LUKS2 token, for example for a TPM | The test of the passphrase is not answered by the LUKS2 token. |
| Static network configuration of the initramfs (`ip=`) | `unlock` works as with DHCP. |
| A server other than Debian 13 | The procedure of [server-setup.md](server-setup.md) applies. |

## Checking a token

The token checks, except the complete cycle, need no server. A separate
configuration file keeps the regular one untouched. `derive` refuses to
write to a terminal; the commands below print only a hash of the
passphrase.

```sh
C=$(mktemp -d)/config.ini
kaltstart --config "$C" init
kaltstart --config "$C" add-host test --host srv01.example.net
kaltstart --config "$C" derive test | sha256sum
kaltstart --config "$C" derive test | sha256sum
```

Both runs must print the same hash. A derivation that fails prints an
error message and the hash of empty input, `e3b0c442...`; its exit status
is visible without the pipeline:

```sh
kaltstart --config "$C" derive test > /dev/null; echo $?
```

For the PIN check, `pin = yes` is changed to `pin = no` in the file `$C`,
and the derivation is repeated:

```sh
kaltstart --config "$C" derive test | sha256sum
```

The PIN protects the passphrase on this token if the derivation fails, or
if the hash differs from the previous one.

A credential without the PIN requirement is created with
`kaltstart --config "$C" init --token nopin --no-pin`.

Afterward the directory of `$C` is removed. The credentials that `init`
created are not stored on the token and need no removal.

Results are welcome as a report; see
[CONTRIBUTING.md](../CONTRIBUTING.md).
