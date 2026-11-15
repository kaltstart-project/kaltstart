# Security model and procedures

This document describes the threat model of kaltstart, the handling of
secrets and the procedures for a lost token or a compromise. Security
issues are reported as described in [SECURITY.md](../SECURITY.md).

## Status

kaltstart has not been verified with a physical token. The server side was
verified on Debian 13 with a stand-in program in place of the token
([verification.md](verification.md)). The properties below
describe the design; where a statement was not checked on a real system, it
says so.

## Threat model

| Scenario | Covered | Remarks |
|----------|---------|---------|
| A disk or the entire server is lost, stolen, returned to a hosting provider or disposed of. | Yes | The passphrase is not stored on the disk and cannot be derived without the token. Whether the PIN is required in addition depends on the token; see [The token PIN](#the-token-pin). The typed passphrase keeps its own keyslot, so the disk is only as strong as the weakest keyslot that remains on it. |
| The unencrypted boot files (kernel, initramfs) are modified, and the server is unlocked afterward. | No | Requires Secure Boot with keys under the operator's control and an initramfs that is covered by the signature (unified kernel image). |
| The SSH host key of the initramfs is copied from the boot partition, and the server is impersonated. | No | Requires a host key that is bound to a TPM 2.0 and the measured boot state, or a per-boot host key that is verified through the BMC. |

The pinned known_hosts entry protects against network attackers who have no
access to the boot partition. It does not help in the third scenario,
because the initramfs and the host key it contains are stored unencrypted.

In the second and third scenario the attacker obtains the passphrase that
is submitted at the next unlock, whether it comes from the token or is
typed. The attacker obtains neither the token, nor its PIN, nor the
passphrase that the token derives for any other server.

A passphrase is only a means to decrypt the volume key from a keyslot in
the LUKS header. An attacker who holds a passphrase and has, or had, access
to the header (usually on the same disk as the boot partition) holds the
volume key. Removing or replacing the keyslot afterward does not change
that; see [Procedures](#procedures).

## Components and trust

| Component | Role |
|-----------|------|
| Token | Holds the secret of the credential. The secret never leaves the token. |
| Workstation | Runs the FIDO2 platform (`fido2-assert`) and holds the passphrase in process memory for the duration of a command. A compromised workstation can capture the PIN, every typed passphrase and every derived passphrase, and it can use the administrative access to the servers. |
| Configuration file | Contains the credential ID and one salt per host. Neither is secret, but without them the passphrase cannot be derived. The file decides where a passphrase is sent and which ssh options are used: its integrity matters. kaltstart refuses a file that others can write. |
| Server | Receives the passphrase of its own keyslot. The passphrase is static, so a server, or whoever controlled its pre-boot environment, can use it again as long as the keyslot or a copy of the header exists. The server has no access to the token. |
| Network | Carries the SSH sessions, the TCP readiness checks and the name resolution. |

## What an attacker needs

To decrypt a stolen disk or a copy of it:

1. the token;
2. the token PIN, on a token that enforces it;
3. the credential ID and the salt of the host from the configuration file.

kaltstart requests user presence (a touch) for every derivation. A touch
is no obstacle for a person who holds the token. Its purpose is to keep
software on the workstation from using the token unnoticed: CTAP 2.1
requires an authenticator to refuse `hmac-secret` without user presence.
For tokens that implement only CTAP 2.0 this has not been verified.

To unlock a server through its initramfs, the SSH private key that the
initramfs accepts and network access to it are needed in addition.

Proof that the server runs unmodified software is not among these factors
(second and third scenario).

## The token PIN

With `pin = yes` (the default) kaltstart requests user verification by PIN
for every derivation. That request is made by the workstation. Whether a
person who holds the token and the configuration file can obtain the
passphrase without the PIN depends on the token:

- `init` requests the credential protection level 3
  (`userVerificationRequired`, extension `credProtect`) for the new
  credential unless `--no-pin` is given. A token that implements the
  extension refuses to use the credential without user verification. A
  token that does not implement it ignores the request.
- A token that implements `hmac-secret` as specified in CTAP 2.1 keeps two
  secrets per credential, one for requests with user verification and one
  for requests without. A request without the PIN then yields a different
  value, which is not the passphrase.
- CTAP 2.0 specifies a single secret per credential. On a token that
  implements `hmac-secret` in that way and does not implement
  `credProtect`, the PIN does not protect the passphrase.

kaltstart does not verify which of these cases applies. The check that
decides it for a given token is described in
[verification.md](verification.md#checking-a-token). Until it has
been carried out for the token in use, the PIN must not be counted as a
factor.

The PIN is protected by the retry counter of the token. A token whose PIN
is blocked has to be reset, and a reset (`fido2-token -R`, which does not
ask for confirmation) destroys every credential on it. kaltstart cannot
unlock with a token that has been reset; the fallbacks described under
[Fallback access](#fallback-access) exist for this case.

## Secret handling

- The passphrase exists in the memory of `fido2-assert` and of kaltstart,
  on the pipe between them, and on the standard input of `ssh`. kaltstart
  never places it in a command line, the environment, a local file, verbose
  output or an error message. Core files are disabled for kaltstart and the
  programs it starts.
- `derive` writes the passphrase to its standard output and refuses to
  write to a terminal unless `--allow-tty` is given.
- Nothing that ssh or the remote side prints during a run without a
  terminal reaches the terminal unfiltered: standard error is passed on
  line by line as it arrives, standard output after the run has ended, both
  with control characters escaped. If the remote side echoes the
  passphrase, it is replaced by `[passphrase removed]`. The one step of
  `enroll` in which cryptsetup asks for an existing passphrase runs on a
  terminal; its output is not filtered.
- `enroll` tests and verifies a keyslot with the passphrase on standard
  input, the way `unlock` delivers it. Only when cryptsetup has to ask for
  an existing passphrase on the terminal is the new passphrase written to a
  file in `/run` on the server (mode 0600). The file is compared with what
  was sent before a keyslot is created from it, and it is removed
  afterward, also after errors and on SIGINT, SIGTERM, SIGHUP or SIGQUIT.
  Removal is not possible after SIGKILL or after loss of the connection; if
  the removal fails, kaltstart names the file that has to be removed
  manually. `/run` is a tmpfs; on a server with unencrypted swap space its
  content can reach the disk.
- An ssh process that carries the passphrase is ended when kaltstart is
  interrupted.
- Host names, user names and ssh options are validated before they are
  passed to `ssh`.

## SSH connections

Both connections, to the initramfs and to the running system, are made
with options that precede everything that can be configured, so that
neither the configuration file of kaltstart nor the SSH configuration of
the user can override them:

| Option | Effect |
|--------|--------|
| `StrictHostKeyChecking=yes` | The host key must already be known. An unknown key is never accepted. |
| `UpdateHostKeys=no`, `VerifyHostKeyDNS=no` | No host key is learned from the server or from DNS. |
| `ControlMaster=no`, `ControlPath=none` | A connection that was opened earlier under other rules is not reused. |
| `ForwardAgent=no`, `ForwardX11=no`, `ClearAllForwardings=yes` | The remote side gets no access to the agent, the display or the local network. |

A flag of ssh, unlike `-o`, would set its option directly. `ssh_options`
and `admin_ssh_options` therefore accept only a fixed set of flags, which
contains none that switches a forwarding or connection sharing on.

The connection to the initramfs additionally disables password and
keyboard-interactive authentication, so that a server cannot show a prompt
of its own. If `known_hosts` is set, ssh reads no other known_hosts file
for this connection; a `KnownHostsCommand` in the SSH configuration of the
user remains in effect.

Identity and known_hosts of the connection to the running system come from
the SSH configuration of the user.

The connection to a jump host (`-J`) is made by a separate ssh process
under the SSH configuration of the user. The options above apply to the
connection to the server, whose host key is still checked end to end.

## Fallback access

Two fallbacks should be kept in place, because a token can fail, be lost
or be reset.

- **Typed passphrase.** The restricted SSH key provides an interactive
  prompt when a terminal is requested (see also
  [server-setup.md](server-setup.md#8-verify-the-typed-fallback)):

  ```sh
  ssh -t -p 2222 -i ~/.ssh/id_ed25519_unlock \
      -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
      -o UserKnownHostsFile=~/.ssh/known_hosts.initramfs \
      root@srv01.example.net cryptroot-unlock
  ```

  The typed passphrase should be unique per server: a modified or
  impersonated pre-boot environment learns it like any other passphrase
  that is submitted.

- **Second token.** Every token has its own credential and therefore its
  own passphrase and keyslot:

  ```sh
  kaltstart init --token backup
  kaltstart enroll srv01 --token backup
  kaltstart unlock srv01 --token backup
  ```

  `add-host` ties a host to the token section that exists at that time. A
  host section without a `token` key requires `--token` as soon as the
  configuration file contains more than one token section.

The fallbacks depend on files on the workstation: the configuration file
(credential IDs and salts) and the SSH key for the initramfs. A backup of
both, or a second authorized key that is kept elsewhere, preserves access
if the workstation is lost.

## Procedures

The procedures have not been exercised as a whole. Run on Debian 13 with
cryptsetup 2.7.5 were: `enroll` with its keyslot reports, the removal of a
passphrase with `cryptsetup luksRemoveKey --key-file -` (a passphrase in
one keyslot, in two keyslots, and empty input), `cryptsetup luksDump`, and
`cryptsetup luksKillSlot --key-file -` with empty input.

### Keyslot numbers

`enroll` reports the keyslot of every device, for a new keyslot as well as
for one that exists (`already enrolled (keyslot N)`). The numbers should be
recorded per host and token: they identify the keyslots of a token that is
no longer available.

### Rotating the passphrases of a host

Rotation replaces the passphrases that the tokens derive for one host. It
protects against a party that holds an old passphrase but never had access
to the LUKS header. It does not replace the volume key.

The salt belongs to the host, so a new salt changes the passphrase of
every token. All tokens that are enrolled for the host take part.

1. Copy the section of the host in the configuration file under a new
   name, for example `[host srv01-new]`, and replace its `salt` with a new
   value (`head -c 32 /dev/urandom | base64`).
2. Enroll every token: `kaltstart enroll srv01-new --token NAME`.
3. Reboot the server and unlock it with one token:
   `kaltstart unlock srv01-new --token NAME`. For every other token,
   `kaltstart enroll srv01-new --token NAME` must report
   `already enrolled`.
4. Remove the previous passphrase of every token from every LUKS device.
   The command is repeated until cryptsetup reports
   `No key available with this passphrase` (exit status 2), so that a
   passphrase that occupies more than one keyslot is removed completely:

   ```sh
   kaltstart derive srv01 --token NAME | ssh root@srv01.example.net \
       'cryptsetup luksRemoveKey --key-file - DEVICE'
   ```

   The SSH login must not ask for a password or a key passphrase, because
   the PIN prompt of the token uses the same terminal. If `derive` fails,
   cryptsetup receives no input and removes nothing.
5. Remove the previous section from the configuration file and rename the
   new one.

`cryptsetup luksKillSlot` must not be used with `--key-file -` in such a
pipeline: with empty input it removes the keyslot without any check.

### Lost or stolen token

1. Determine the keyslots of the token on every device. If the numbers
   reported by `enroll` were not recorded, they are found by elimination:
   `cryptsetup luksDump DEVICE` lists the keyslots in use,
   `kaltstart enroll HOST --token NAME` reports the keyslot of every
   remaining token, and
   `cryptsetup open --test-passphrase --disable-external-tokens --verbose DEVICE`
   reports the keyslot of the typed passphrase.
2. Remove the keyslots: `cryptsetup luksKillSlot DEVICE N`. cryptsetup asks
   for a remaining passphrase.
3. Remove the `[token NAME]` section from the configuration file, and the
   `token = NAME` key from every host section that names it.

If the finder may be able to use the token (no PIN, a known PIN, or a
token on which the PIN does not protect the passphrase) and may have
obtained the configuration file and a copy of the LUKS header, the volume
key has to be regarded as disclosed (next section).

### Suspected compromise of a server or its boot files

Replacing passphrases is not sufficient. Whoever modified the boot files,
or copied the host key from the boot partition, usually had access to the
LUKS header on the same disk as well, and a passphrase captured afterward
yields the volume key.

1. Do not unlock the server again, neither with the token nor with the
   typed passphrase, before the boot files can be trusted. A passphrase
   submitted to a modified or impersonated pre-boot environment is
   disclosed.
2. If modified boot files may have run while the disk was unlocked, the
   root file system is compromised: reinstall the server on a new LUKS
   container.
3. Otherwise restore kernel, initramfs and boot loader from a trusted
   source, replace the host keys of the initramfs (remove
   `/etc/dropbear/initramfs/dropbear_*_host_key`, create new keys with
   `dropbearkey`, rebuild the initramfs) and pin the new key as described
   in [server-setup.md](server-setup.md).
4. Replace the volume key (`cryptsetup reencrypt DEVICE`, LUKS2), then
   every passphrase that was submitted while the environment was suspect:
   the derived ones as described above, the typed one with
   `cryptsetup luksChangeKey`.
5. Only then reboot and unlock.

### Compromised workstation

The procedure is carried out from a workstation that is known to be clean.

To be regarded as disclosed: the token PIN; the SSH key for the initramfs;
the administrative SSH access to the running systems; the passphrase of
every host in the configuration file, because software on the workstation
can request a derivation for any salt whenever the token is touched; and
every typed passphrase that was entered on the workstation, during
`enroll` or through the fallback.

1. Replace the SSH key in the `authorized_keys` file of every initramfs,
   and the administrative credentials.
2. Rotate the passphrases of all hosts for all tokens, and replace the
   typed passphrases (`cryptsetup luksChangeKey`).
3. Change the token PIN.
4. If the attacker may have used the administrative access, treat the
   servers as compromised (previous section).

## Hardening outside the scope of kaltstart

None of the following measures is provided or checked by kaltstart.

- Secure Boot with keys under the operator's control and a signed unified
  kernel image, so that a modified initramfs does not start.
- A TPM 2.0 that releases the SSH host key of the initramfs only in the
  measured boot state, or a per-boot host key whose fingerprint is verified
  out of band through the BMC.
- A FIDO2-backed SSH key (`ed25519-sk`, `ecdsa-sk`) for the login to the
  initramfs. The upstream changelog of dropbear lists server support for
  such keys since version 2022.82 and the `authorized_keys` options
  `no-touch-required` and `verify-required` since version 2022.83. The
  combination with kaltstart is untested; dropbear ignores a key whose
  options it does not recognize.
- Network restrictions for the SSH port of the initramfs (firewall, VPN or
  a management network).
- A backup of the LUKS header, kept offline, before keyslots are added or
  removed.
