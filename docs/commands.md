# Command reference

```text
kaltstart [--config PATH] [-v|--verbose] [--version] COMMAND ...
```

The global options precede the command.

| Global option | Description |
|---------------|-------------|
| `--config PATH` | Configuration file. Default: `$XDG_CONFIG_HOME/kaltstart/config.ini`, or `~/.config/kaltstart/config.ini` (see [configuration.md](configuration.md)). |
| `-v`, `--verbose` | Prints the command lines that are run, and a traceback after an internal error. The passphrase is never part of a command line. |
| `--version` | Prints the version and exits. |

Messages of kaltstart are written to standard error with the prefix
`kaltstart: `. Standard output is used for data only (`derive`, `list`,
`--version`, `--help`). The fido2 tools write their own prompts and
messages to the terminal.

SIGINT, SIGTERM, SIGHUP and SIGQUIT are handled alike: a running ssh
process is ended, cleanup runs, the message `kaltstart: interrupted` is
printed, and the exit status is 130. A signal that was already ignored
when the program started (`nohup`) remains ignored.

## Exit status

| Status | Meaning |
|--------|---------|
| 0 | Success. |
| 1 | Internal error, or the output could not be written. |
| 2 | Usage or configuration error; a failed `check`. |
| 3 | Token error: fido2-tools not found, no device or several devices, or no usable secret. |
| 4 | SSH or transport error, including a host key mismatch and a rejected SSH key. Also reported when the connection is lost after the passphrase was delivered and the start cannot be confirmed, and when `enroll` could not remove its key file from the server. |
| 5 | The server rejected the passphrase, did not read it, or did not confirm it in time. For `enroll`: a device cannot be used, or adding or verifying a keyslot failed. |
| 6 | Timeout: the initramfs port did not open, or the system did not start. |
| 130 | Interrupted by SIGINT, SIGTERM, SIGHUP or SIGQUIT. |

## SSH connections

kaltstart starts the `ssh` program of the system for two kinds of
connections.

| Connection | Command line |
|------------|--------------|
| Initramfs (`unlock`) | `ssh -T -p PORT FORCED INITRAMFS [-o UserKnownHostsFile=FILE -o GlobalKnownHostsFile=/dev/null] [-o IdentitiesOnly=yes -i FILE] SSH_OPTIONS DEFAULTS -- USER@HOST REMOTE_COMMAND` |
| Running system (`enroll`) | `ssh -T [-p ADMIN_PORT] FORCED ADMIN_SSH_OPTIONS DEFAULTS -- ADMIN_USER@ADMIN_HOST COMMAND`; for the one step that needs a terminal, `-t -e none` takes the place of `-T` |

| Group | Options |
|-------|---------|
| `FORCED` | `-o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o VerifyHostKeyDNS=no -o ControlMaster=no -o ControlPath=none -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes` |
| `INITRAMFS` | `-o PasswordAuthentication=no -o KbdInteractiveAuthentication=no` |
| `DEFAULTS` | `-o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=3` |

ssh uses the first value it obtains for an option, and it reads the
command line before its configuration files. The forced options therefore
cannot be overridden by `ssh_options`, `admin_ssh_options` or the SSH
configuration of the user. The defaults yield to `ssh_options` and
`admin_ssh_options` only; they take precedence over `ConnectTimeout`,
`ServerAliveInterval` and `ServerAliveCountMax` in the SSH configuration
of the user. The host key of either system must be known before kaltstart
is used.

A run without a terminal is ended if it produces no result within 300
seconds or if the remote command writes more than one mebibyte to standard
output. Nothing that ssh or the remote side prints during such a run
reaches the terminal unfiltered. Standard error is printed line by line as
it arrives, as `kaltstart: ssh: ...`; the standard output of the remote
command is printed after the run has ended, as `kaltstart: remote: ...`.
Control characters are escaped in both. `enroll` evaluates the standard
output of its passphrase tests and of the file comparison without printing
it.

## init

```text
kaltstart init [--token NAME] [--rp-id ID] [--device DEV] [--no-pin]
```

Creates a non-resident credential with the `hmac-secret` extension on the
token and appends a `[token NAME]` section with the credential ID to the
configuration file. The token asks for a touch and, if it requires one,
for its PIN. The command fails if the section already exists or the file
cannot be written; both are checked before the token is used.

Without `--no-pin` the credential is requested with the protection level 3
(`fido2-cred -M -h -c 3`): a token that implements the `credProtect`
extension then refuses to use the credential without the PIN. Whether the
token applied the request is not checked; see
[verification.md](verification.md#checking-a-token).

| Option | Default | Description |
|--------|---------|-------------|
| `--token NAME` | `main` | Name of the token section. |
| `--rp-id ID` | `kaltstart` | Relying party ID of the credential. |
| `--device DEV` | auto-detect | FIDO2 device, for example `/dev/hidraw5`. |
| `--no-pin` | | Creates a credential that is used without the PIN (`fido2-cred -M -h`) and writes `pin = no`. |

## add-host

```text
kaltstart add-host NAME --host H [--port N] [--user U] [--identity F]
                   [--known-hosts F] [--booted-port N] [--token T]
                   [--device-on-server DEV]
```

Appends a `[host NAME]` section with a new random 32-byte salt. All values
are validated before anything is written, and a token section named with
`--token` must exist. The command fails if the section already exists.
Keys without a corresponding option are added with an editor.

| Option | Default | Description |
|--------|---------|-------------|
| `--host H` | required | Host name or address of the server in the initramfs. |
| `--port N` | `22` | SSH port of the initramfs. |
| `--user U` | `root` | Login user of the initramfs. |
| `--identity F` | none | SSH private key for the initramfs. An absolute path, or one that starts with `~`. |
| `--known-hosts F` | none | known_hosts file that contains the host key of the initramfs. An absolute path, or one that starts with `~`. |
| `--booted-port N` | none | SSH port of the running system, used to confirm the start. |
| `--token T` | the only token section, if there is exactly one | Token section used for this host. |
| `--device-on-server DEV` | none | LUKS device of the server. May be given several times. |

## enroll

```text
kaltstart enroll HOST [--token T] [--device DEV] [--device-on-server DEV]
                 [--existing-keyfile PATH_ON_SERVER]
```

Adds the derived passphrase as an additional keyslot to the LUKS devices of
the running system. The connection uses the `admin_*` keys of the host.

1. For every device, `cryptsetup isLuks DEVICE` is run. This step precedes
   the use of the token: an unreachable server, a device that is not a
   LUKS device and a `sudo` that asks for a password are reported before
   PIN and touch are spent.
2. The passphrase is derived from the token.
3. For every device, the passphrase is tested with
   `cryptsetup open --test-passphrase --disable-external-tokens --verbose --key-file - DEVICE`,
   which reads it from standard input. A device that the passphrase
   already opens is reported as `already enrolled (keyslot N)` and left
   unchanged.
4. For the remaining devices a keyslot is added:
   - Without `--existing-keyfile`, cryptsetup has to ask for an existing
     passphrase on the terminal. The new passphrase is written to the file
     `/run/kaltstart-enroll-<random>` on the server (mode 0600), and the
     file is compared with what was sent (`sha256sum`). For every device,
     `cryptsetup luksAddKey --new-keyfile FILE DEVICE` is run in an SSH
     session with `-t -e none`, so that the escape character of ssh cannot
     interfere with the input.
   - With `--existing-keyfile`, no file is written:
     `cryptsetup luksAddKey --key-file PATH_ON_SERVER --new-keyfile - DEVICE`
     reads the new passphrase from standard input.
5. Every new keyslot is verified with the test of step 3 and reported as
   `verified (keyslot N)`.
6. The file of step 4 is removed, also after errors and interruptions. The
   termination signals are ignored while the removal runs. If it fails, a
   warning names the file.

The keyslot numbers should be recorded; see
[security.md](security.md#keyslot-numbers).

The devices are taken from `--device-on-server` or from the `devices` key.
Without configured devices, the LUKS devices reported by `blkid` on the
server are listed and the command ends with exit status 2, or with 4 if
the SSH connection fails.

| Option | Default | Description |
|--------|---------|-------------|
| `--token T` | see [configuration.md](configuration.md) | Token section to use. |
| `--device DEV` | auto-detect | FIDO2 device on the workstation. |
| `--device-on-server DEV` | `devices` key | LUKS device of the server. May be given several times. |
| `--existing-keyfile PATH_ON_SERVER` | none | Key file on the server that opens an existing keyslot. With this option cryptsetup does not prompt, no terminal is requested and the passphrase is not written to a file. |

| Exit status | Cause |
|-------------|-------|
| 3 | The passphrase could not be derived. Nothing was changed on the server. |
| 4 | An SSH connection failed, the uploaded file did not match, or the file could not be removed from the server. |
| 5 | A device cannot be used, or the test, `luksAddKey` or the verification failed for at least one device. |

## unlock

```text
kaltstart unlock HOST [--token T] [--device DEV] [--wait SECONDS]
                 [--boot-timeout SECONDS]
```

Unlocks the server while it waits in the initramfs.

1. **Readiness.** TCP connections to `host`:`port` are attempted until
   one succeeds, with a pause of two seconds after a failed attempt; an
   attempt is given up after five seconds. No SSH session is opened for
   this check, because an empty input would count as a failed unlock
   attempt on the server. Skipped with `probe = no`.
2. **Derivation.** The passphrase is derived from the token. If this step
   fails, no SSH session is opened.
3. **Submission.** The passphrase is written to the standard input of an
   SSH session that runs `remote_command`. `cryptroot-unlock` answers one
   passphrase prompt per session, so the step is repeated, at most
   `prompts` times. It ends earlier when a session shows no prompt, or
   when the initramfs no longer answers after a submission was accepted.
4. **Confirmation.** If `booted_port` is set, TCP connections to
   `admin_host`:`booted_port` are attempted until one succeeds. Skipped
   with `probe = no`, and if `booted_port` equals `port` on the same
   machine, because the SSH service of the initramfs would answer.

| Option | Default | Description |
|--------|---------|-------------|
| `--token T` | see [configuration.md](configuration.md) | Token section to use. |
| `--device DEV` | auto-detect | FIDO2 device on the workstation. |
| `--wait SECONDS` | `600` | Time limit for step 1, from 0 to 31536000 seconds. `0` means a single attempt. |
| `--boot-timeout SECONDS` | `300` | Time limit for step 4, from 0 to 31536000 seconds. `0` means a single attempt. |

Every session of step 3 is evaluated by the exit status of ssh and by the
line `Please unlock disk ...`, which `cryptroot-unlock` prints on standard
output immediately before it reads the passphrase:

| Result of the session | Evaluation | Exit status |
|-----------------------|------------|-------------|
| 0, prompt seen | The passphrase was accepted for one prompt. The next session follows, up to `prompts`. | 0, or 6 if step 4 finds that the system does not start in time |
| 0, no prompt | No device is waiting. In the first session the passphrase was not tested. After an accepted submission step 3 is complete. | first session: 5; later: 0, or 6 after step 4 |
| 255 or ssh ended by a signal, no prompt | Nothing was delivered. In the first session: connection, host key or authentication problem. After an accepted submission the initramfs has moved on and step 3 is complete; if its port still answers, the submission could not be delivered. | first session: 4; later: 0, or 6 after step 4, or 4 if the port still answers |
| 255 or ssh ended by a signal, prompt seen | The session was lost after the passphrase was delivered. Step 4 decides. | 0 or 4 |
| other status, prompt seen | The server rejected the passphrase. | 5 |
| other status, prompt seen, message `Timeout reached while waiting for PID` | `cryptroot-unlock` waits ten seconds for cryptsetup; the device may still open. Step 4 decides. | 0 or 5 |
| other status, no prompt | The server did not ask for the passphrase, for example because `cryptroot-unlock` timed out. In the first session the command can be repeated. After an accepted submission step 4 decides. | first session: 5; later: 0 or 5 |

Where step 4 decides and no confirmation is possible (no `booted_port`,
`probe = no`, or `booted_port` equal to `port` on the same machine), the
command ends with the status that is not 0.

Without a confirmation, exit status 0 means that every submission that
was made was accepted. The submissions end when the limit `prompts` is
reached, when the server no longer asks, or when the initramfs no longer
answers; with a limit below the number of passphrase prompts the server
keeps waiting. Exit status 0 therefore does not prove that all devices are
open or that the system has started; for that, `booted_port` is set.

## derive

```text
kaltstart derive HOST [--token T] [--device DEV] [--allow-tty]
```

Writes the derived passphrase to standard output: 44 ASCII characters
without a trailing newline. The command refuses to write to a terminal.

In a pipeline the exit status of `derive` is not the status of the
pipeline; a failed derivation writes nothing.

| Option | Default | Description |
|--------|---------|-------------|
| `--token T` | see [configuration.md](configuration.md) | Token section to use. |
| `--device DEV` | auto-detect | FIDO2 device on the workstation. |
| `--allow-tty` | | Permits output to a terminal. |

## check

```text
kaltstart check HOST
```

Validates the local configuration for the commands `unlock` and `enroll`.
The token is not used and the server is not contacted. One line is printed
per check; the exit status is 0 if all checks pass and 2 otherwise.

- owner and permissions of the configuration file: any access for group or
  others fails this check, while the other commands only warn about read
  access
- permissions of its directory: write access for group or others fails
  this check
- presence of `fido2-assert`, `fido2-token`, `ssh` and `ssh-keygen`
- validity of the host section and of the token section that is used
  without `--token`
- existence of the `identity` and `known_hosts` files
- presence of a known_hosts entry for the host (`ssh-keygen -F`, with
  `[HOST]:PORT` for ports other than 22). Without a `known_hosts` key the
  default known_hosts file of the user is searched.

A note is printed if another host section uses the same salt.

## list

```text
kaltstart list
```

Prints the configured tokens and hosts. Credential IDs and salts are
abbreviated. All sections are validated, including the token section that
a host names. A warning is printed for host sections that use the same
salt.
