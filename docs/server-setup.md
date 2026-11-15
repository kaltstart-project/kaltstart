# Server setup

This document describes how a Debian 13 server is prepared for kaltstart.
Only distribution packages are installed; nothing from this repository is
copied to the server. Other Debian-based distributions that use
initramfs-tools provide the same packages but have not been tested.

The procedure follows the package documentation in
`/usr/share/doc/cryptsetup/README.Debian.gz` (section 8) and
`/usr/share/doc/dropbear-initramfs/README.initramfs`. It was carried out on
Debian 13 with dropbear-initramfs 2025.89 and cryptsetup 2.7.5, with a
stand-in program in place of a physical token.

Out-of-band console access (BMC, hypervisor console or the rescue system of
the hosting provider) must be available until the complete procedure has
succeeded once, and again whenever one of the files below is changed.

Conventions used in the examples:

| Item | Value |
|------|-------|
| Server | `srv01.example.net` |
| SSH port of the initramfs | 2222 |
| SSH port of the running system | 22 |
| SSH key for unlocking | `~/.ssh/id_ed25519_unlock` |
| known_hosts file for the initramfs | `~/.ssh/known_hosts.initramfs` |

Commands on the server are run as root.

## 1. Install the packages

```sh
apt install dropbear-initramfs cryptsetup-initramfs
```

The installation creates separate SSH host keys for the initramfs in
`/etc/dropbear/initramfs/`. They differ from the host keys of the running
system, because the initramfs is stored unencrypted.

## 2. Assign a fixed network address

The initramfs configures its network by DHCP unless the kernel parameter
`ip=` defines a static configuration.

A fixed address is required for reliable operation: either a reservation
in the DHCP server or a static configuration. The DHCP client of the
initramfs and that of the running system can identify themselves
differently, so that a DHCP server holds two leases for the same machine.
During the verification the initramfs and the running system received
different addresses, which were exchanged at every boot.

A static configuration is given on the kernel command line in the form
`ip=ADDRESS::GATEWAY:NETMASK:HOSTNAME:INTERFACE:off` (see the kernel
documentation on `nfsroot`), for example through `GRUB_CMDLINE_LINUX` in
`/etc/default/grub`, followed by `update-grub`. This variant was not part
of the verification.

The pinned known_hosts entry and the `host` key of the configuration file
refer to the address of the initramfs. If the running system uses another
address, `admin_host` must be set.

The driver of the network interface must be part of the initramfs (see
the dropbear-initramfs documentation), and a firewall in front of the
server must admit the SSH port of the initramfs.

## 3. Configure the SSH service of the initramfs

`/etc/dropbear/initramfs/dropbear.conf`:

```sh
DROPBEAR_OPTIONS="-p 2222 -s -j -k"
```

| Option | Effect |
|--------|--------|
| `-p 2222` | Listens on a separate port, so that the initramfs and the running system do not share a known_hosts entry. |
| `-s` | Disables password logins. |
| `-j`, `-k` | Disable local and remote port forwarding. |

## 4. Authorize a dedicated key with a forced command

A dedicated key pair is created on the workstation:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_unlock -C initramfs-unlock
```

The public key is added to `/etc/dropbear/initramfs/authorized_keys` on the
server as a single line:

```text
no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="/bin/cryptroot-unlock" ssh-ed25519 AAAA... initramfs-unlock
```

The forced command restricts the key to unlocking. The options `no-pty` and
`restrict` must not be added: the typed fallback in section 8 requires a
terminal, and `restrict` includes `no-pty`. dropbear ignores keys that
carry options it does not recognize.

The key is needed for the token as well as for the typed fallback. A
backup of the private key, or a second authorized key that is kept
elsewhere, preserves access if the workstation is lost.

## 5. Several LUKS devices

kaltstart adds an ordinary passphrase keyslot. For a server whose only
LUKS device holds the root file system, `/etc/crypttab` needs neither a
keyscript nor an additional option:

```text
root_crypt UUID=<uuid> none luks
```

`cryptroot-unlock` handles the devices that the initramfs opens: those
that are needed for the root file system, and every device whose crypttab
entry carries the option `initramfs` (see crypttab(5)). Any other device is
opened later; if it needs a passphrase, the prompt appears on the local
console, where neither kaltstart nor the typed fallback can answer it. Such
an entry needs the option `initramfs` or a key file on the root file
system.

If the initramfs opens several LUKS devices, one of two cases applies:

- **Without a keyscript.** The initramfs asks for one passphrase per
  device, and in non-interactive mode `cryptroot-unlock` answers one
  prompt per invocation. The `prompts` key of the host is set to the
  number of prompts or to a higher value; kaltstart submits the passphrase
  until the server no longer asks. The passphrase must be enrolled on
  every device.
- **With `keyscript=decrypt_keyctl`.** Devices that carry the same key
  identifier in the third field are opened with a single passphrase, which
  is cached for 60 seconds. `prompts` remains 1. The keyscript needs the
  program `keyctl` from the package `keyutils`, which Debian 13 does not
  install by default:

  ```sh
  apt install keyutils
  ```

  ```text
  root_crypt  UUID=<uuid> luks_key luks,keyscript=decrypt_keyctl
  data1_crypt UUID=<uuid> luks_key luks,initramfs,keyscript=decrypt_keyctl
  ```

A change to `/etc/crypttab` affects the boot process. After every change
the initramfs is rebuilt (section 6) and the typed fallback is verified
again (section 8) while console access is available.

## 6. Rebuild the initramfs

The initramfs is rebuilt after every change to the files above:

```sh
update-initramfs -u -k all
```

Before the first reboot, the content of the new initramfs is checked. The
command must print the SSH service, the authorized keys and
`cryptroot-unlock`:

```sh
lsinitramfs /boot/initrd.img-$(uname -r) | grep -E 'sbin/dropbear$|authorized_keys$|bin/cryptroot-unlock$'
```

## 7. Pin the host key of the initramfs

The public host key is read over the existing, trusted connection to the
running system, not from whatever answers on port 2222:

```sh
ssh root@srv01.example.net \
    dropbearkey -y -f /etc/dropbear/initramfs/dropbear_ed25519_host_key
```

On a server without root login over SSH the command is run through sudo
(`ssh USER@srv01.example.net sudo dropbearkey ...`).

`dropbearkey -y` prints the public key and its fingerprint. The line that
starts with `ssh-ed25519` is stored, without its comment, in a dedicated
known_hosts file in the form `[host]:port key`:

```text
[srv01.example.net]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

For port 22 the entry is written without brackets and port. The host part
must be identical to the `host` key of the configuration file.

kaltstart never accepts an unknown host key, neither for the initramfs nor
for the running system.

## 8. Verify the typed fallback

After a reboot the server is unlocked manually, before the token is relied
upon:

```sh
ssh -t -p 2222 -i ~/.ssh/id_ed25519_unlock \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=~/.ssh/known_hosts.initramfs \
    root@srv01.example.net cryptroot-unlock
```

With a terminal (`-t`), `cryptroot-unlock` prompts for the passphrase until
all devices are open. The number of prompts is the smallest value for the
`prompts` key. This path is the means of access whenever the token is
unavailable and must work before the setup continues.

Further fallbacks, a second token and backups of the files on the
workstation, are described in [security.md](security.md#fallback-access).

## 9. Enroll the token and unlock

The remaining steps are carried out on the workstation and are described
in the [quick start](../README.md#quick-start): `kaltstart init`,
`kaltstart add-host`, `kaltstart check`, `kaltstart enroll` and, after the
next reboot, `kaltstart unlock`.

## Notes

- **No root login over SSH.** If root cannot log in to the running system,
  `admin_user` and `admin_sudo = yes` are set in the `[host ...]` section.
  `enroll` then runs its remote commands through sudo, which must not ask
  for a password in the steps that have no terminal.
- **Jump host.** For a server that is reachable only through a jump host,
  `ssh_options = -J bastion.example.net` and `probe = no` are set. `unlock`
  then does not wait for the initramfs port and does not confirm the start.
- **Wrong passphrases.** Wrong passphrases count against the `tries` limit
  of the crypttab entry (default 3); the third one is answered with
  `maximum number of tries exceeded`. On Debian 13 the initramfs prompted
  again afterward, while it waited for the root device, and still accepted
  the correct passphrase without a reboot.
- **Exit status 5.** `unlock` reports exit status 5 in three cases: the
  passphrase was rejected; the server did not read it (no
  `Please unlock disk` line was received, for example because
  `cryptroot-unlock` timed out while waiting for the prompt, or because no
  device was locked); or `cryptroot-unlock` stopped waiting before
  cryptsetup had finished and the start could not be confirmed. Only in
  the first case was a passphrase tested and refused.
- **Number of keyslots.** `cryptroot-unlock` waits ten seconds for
  cryptsetup. cryptsetup tries the keyslots one after the other, and every
  attempt takes about as long as the unlock time that was set for that
  keyslot (in the order of two seconds unless configured otherwise). With
  many keyslots a correct passphrase may not be confirmed in time; `unlock`
  then relies on the start confirmation.
- **Memory.** cryptsetup may warn that a keyslot requires more memory than
  is available. The memory needed to open a keyslot is fixed when the
  keyslot is created and must be available in the initramfs.

All configuration keys are described in
[configuration.md](configuration.md).
