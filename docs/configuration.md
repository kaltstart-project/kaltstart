# Configuration reference

kaltstart reads a single INI file.

| Item | Value |
|------|-------|
| Default location | `$XDG_CONFIG_HOME/kaltstart/config.ini`, or `~/.config/kaltstart/config.ini` if `XDG_CONFIG_HOME` is not set |
| Override | `kaltstart --config PATH ...` |
| Permissions | The directory is created with mode 0700, the file with mode 0600. A file that is writable by group or others, or owned by a user other than the invoking user or root, is refused. A warning is printed if the file is readable by group or others. |

General rules:

- `init` and `add-host` append sections. Existing content is never
  rewritten; every other change is made with an editor.
- Section headers have the form `[token NAME]` or `[host NAME]`. A name
  starts with a letter or a digit, followed by up to 63 letters, digits or
  the characters `.`, `_` and `-`. Section names are case-sensitive, key
  names are not.
- Unknown sections, including `[DEFAULT]`, and unknown keys are
  configuration errors (exit status 2). A section is validated when it is
  used; `list` validates all sections.
- A comment is a line that starts with `#` or `;`. A `#` or `;` after a
  value is part of the value.
- Boolean keys accept `yes`, `no`, `true`, `false`, `on`, `off`, `1` and
  `0`.
- A file that does not exist is treated as empty.
- The file contains no secrets, but the credential IDs and the salts are
  required to derive the passphrases: a backup of the file is necessary.
  Its content decides where a passphrase is sent, so it must not be
  writable by anyone else.

An example configuration file is provided in
[examples/config.ini](../examples/config.ini).

## `[token NAME]`

One section per FIDO2 token. `init` writes the section.

| Key | Default | Description |
|-----|---------|-------------|
| `credential_id` | required | Credential ID as printed by `fido2-cred`, Base64-encoded. |
| `rp_id` | `kaltstart` | Relying party ID for which the credential was created. |
| `pin` | `yes` | Whether user verification by PIN is requested for every derivation. A credential that `init` created without `--no-pin` cannot be used with `pin = no` on a token that implements `credProtect`; on other tokens the value that is derived may differ. Changing this key after enrollment can therefore make the derivation fail or yield a value that does not open the enrolled keyslots; the keyslots themselves remain unchanged. See [SECURITY.md](security.md#the-token-pin). |
| `device` | auto-detect | Path of the FIDO2 device, for example `/dev/hidraw5`. Without this key the only device listed by `fido2-token -L` is used; no device or several devices are an error. |

The token used for a host is selected in this order: the `--token` option,
the `token` key of the host, the only `[token ...]` section of the file. If
the host has no `token` key and the file contains several token sections,
`--token` is required. `add-host` writes the `token` key when exactly one
token section exists.

## `[host NAME]`

One section per server. `add-host` writes the section with the keys that
correspond to its options and with a new salt.

Every host needs its own salt. Two host sections with the same salt yield
the same passphrase for a token; that is intended only if both sections
describe the same server, for example with and without a jump host. `list`
and `check` point out such sections.

### Derivation

| Key | Default | Description |
|-----|---------|-------------|
| `salt` | required | Per-host salt: Base64 of exactly 32 bytes. Used by `derive`, `enroll` and `unlock`. |
| `token` | none | Name of the token section used when `--token` is not given. |

### Initramfs connection

These keys are used by `unlock`.

| Key | Default | Description |
|-----|---------|-------------|
| `host` | required | Host name or address of the server while it waits in the initramfs. Also the default of `admin_host`. |
| `port` | `22` | SSH port of the initramfs. |
| `user` | `root` | Login user of the initramfs. |
| `identity` | none | SSH private key accepted by the initramfs. Sets `-o IdentitiesOnly=yes -i FILE`. |
| `known_hosts` | none | known_hosts file that contains the host key of the initramfs. Sets `-o UserKnownHostsFile=FILE -o GlobalKnownHostsFile=/dev/null`: the file is then the only known_hosts file that ssh reads. A `KnownHostsCommand` in the SSH configuration of the user remains in effect. |
| `remote_command` | `cryptroot-unlock` | Command passed to the server. A forced command in `authorized_keys` takes precedence on the server. |
| `prompts` | `1` | Upper limit for the number of passphrase submissions (1 to 1000), one SSH session each. `unlock` stops earlier when the server no longer asks. The value must be at least the number of passphrase prompts that the typed fallback shows; see [server-setup.md](server-setup.md#5-several-luks-devices). |
| `probe` | `yes` | Whether readiness is checked with TCP connections from the workstation. With `no`, `unlock` neither waits for the initramfs port nor confirms the start. Required for servers that are reachable only through a jump host or an SSH configuration alias. |
| `booted_port` | none | SSH port of the running system. If set, `unlock` waits for this port on `admin_host` to confirm the start. The confirmation is skipped if the port equals `port` and `admin_host` is the same machine as `host`. |
| `ssh_options` | none | Additional `ssh` options for the initramfs connection, split like a shell command line, for example `-J bastion.example.net`. |

`identity` and `known_hosts` are local paths. They must be absolute or
start with `~`, and they must not contain white space, quotes, `%` or `#`.

`ssh_options` and `admin_ssh_options` accept a fixed set of ssh options
and their arguments: `-4`, `-6`, `-C`, `-q`, `-v`, and with an argument
`-b`, `-B`, `-c`, `-E`, `-F`, `-i`, `-I`, `-J`, `-m`, `-o` and `-P`. Any
other word is a configuration error. Flags that would switch a forwarding
or connection sharing on again (`-A`, `-X`, `-Y`, `-M`, `-S`) are among
those that are rejected; everything else that ssh offers is available
through `-o`. The options that kaltstart forces for every connection are
listed in [commands.md](commands.md#ssh-connections); they cannot be
overridden here.

`port` and `user` are always passed to ssh. If `host` is an alias from the
SSH configuration of the user, the `Port` and `User` settings of the alias
therefore have no effect, and `check` looks up the alias name in the
known_hosts file.

### Running system

These keys are used by `enroll`, and `admin_host` is used by `unlock` for
the start confirmation. Identity and known_hosts of this connection come
from the SSH configuration of the user. The host key must already be
known.

`enroll` opens several SSH connections in a row; connection sharing is
switched off. An agent or a key without a passphrase avoids repeated
prompts. With a FIDO2-backed SSH key every connection needs a touch, and
ssh may not announce the request, because its standard error is not a
terminal in these runs.

| Key | Default | Description |
|-----|---------|-------------|
| `admin_host` | value of `host` | Host name or address of the running system. Required if the running system uses an address other than that of the initramfs. |
| `admin_port` | none | SSH port of the running system for `enroll`. Without this key the SSH configuration of the user applies (port 22 unless configured otherwise). Independent of `booted_port`. |
| `admin_user` | `root` | Login user of the running system. Always passed to ssh. |
| `admin_sudo` | `no` | Runs the remote commands of `enroll` through `sudo`. The steps without a terminal use `sudo -n`; sudo must therefore work without a password for them. |
| `admin_ssh_options` | none | Additional `ssh` options for the connection to the running system. |
| `devices` | none | LUKS devices of the server as absolute paths, separated by commas or white space. Persistent names such as `/dev/disk/by-uuid/...` are recommended, because kernel device names can change between boots. |
