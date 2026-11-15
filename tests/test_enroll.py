# SPDX-License-Identifier: GPL-2.0-only
"""Tests for enroll, the command that talks to the running system through (stubbed) ssh."""

import os
import re
import shlex
import signal

from support import (CRED_ID, DEFAULTS, FORCED, INSTALLATION_KEY, OTHER_CRED_ID, SALT, SIGNAL_NAMES, CliTestCase,
                     IsolatedTestCase, cli, expected_secret)

SECRET = expected_secret()
ASKING = "kaltstart: asking token 'main' on /dev/hidraw5: enter the PIN if asked, then touch the token"
# The test of a passphrase: cryptsetup reads it from standard input and names the keyslot that it opens.
TEST = "cryptsetup open --test-passphrase --disable-external-tokens --verbose --key-file - "
KEY_FILE = r"/run/kaltstart-enroll-[0-9a-f]{16}"
NO_KEY = "kaltstart: ssh: No key available with this passphrase."
PROMPT = "Enter any existing passphrase: "  # printed by the stub of ssh for cryptsetup on a terminal


def checking(device):
    return f"kaltstart: {device}: checking whether a keyslot already opens with this passphrase"


class EnrollTests(CliTestCase):
    def setUp(self):
        super().setUp()
        # The keys of the initramfs connection (first line) must not show up on the command lines for the running system.
        self.write_host(port=2222, extra=(
            "identity = /keys/id_unlock\nknown_hosts = /keys/kh\nssh_options = -4\n"
            "admin_host = admin.example.net\nadmin_port = 2200\nadmin_ssh_options = -o ConnectTimeout=9\n"
            "devices = /dev/sda3"))

    def admin_argv(self, command, terminal=False):
        """The arguments of ssh for the running system as setUp configures it."""
        return ((["-t", "-e", "none"] if terminal else ["-T"]) + ["-p", "2200"] + FORCED + ["-o", "ConnectTimeout=9"]
                + DEFAULTS + ["--", "root@admin.example.net", command])

    def enroll(self, *args, env=None):
        """Run enroll. Returns the exit status, the lines that were printed and the remote commands."""
        seen = len(self.calls("ssh"))
        result = self.run_cli("enroll", "srv", *args, env=env)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(SECRET, result.stderr)
        return result.returncode, result.stderr.decode().splitlines(), [command for _, command in self.remote_commands(seen)]

    def key_file(self, commands):
        """The name of the key file on the server, taken from the last command, which has to be its removal."""
        removal = re.fullmatch(f"(?:sudo -n )?rm -f ({KEY_FILE})", commands[-1])
        self.assertTrue(removal, commands)
        return removal.group(1)

    def test_happy_path(self):
        self.write_host(port=2222, device=None, extra=(
            "identity = /keys/id_unlock\nknown_hosts = /keys/kh\nssh_options = -4\n"
            "admin_host = admin.example.net\nadmin_port = 2200\nadmin_ssh_options = -o ConnectTimeout=9\n"
            "devices = /dev/sda3, /dev/sdb3"))
        status, lines, commands = self.enroll()
        self.assertEqual(status, 0, lines)
        key = self.key_file(commands)
        expected = [
            # Before the token is used: is the server reachable, is every device a LUKS device?
            ("-T", "cryptsetup isLuks /dev/sda3", b""),
            ("-T", "cryptsetup isLuks /dev/sdb3", b""),
            # Which devices lack the passphrase?
            ("-T", TEST + "/dev/sda3", SECRET),
            ("-T", TEST + "/dev/sdb3", SECRET),
            # The passphrase as a file that is compared with what was sent.
            ("-T", f"umask 077 && cat > {key}", SECRET),
            ("-T", f"sha256sum {key}", b""),
            # cryptsetup asks for an existing passphrase: a terminal, and the new keyslot is tested at once.
            ("-t", f"cryptsetup luksAddKey --new-keyfile {key} /dev/sda3", b""),
            ("-T", TEST + "/dev/sda3", SECRET),
            ("-t", f"cryptsetup luksAddKey --new-keyfile {key} /dev/sdb3", b""),
            ("-T", TEST + "/dev/sdb3", SECRET),
            ("-T", f"rm -f {key}", b""),
        ]
        self.assertEqual(self.remote_commands(), [(flag, command) for flag, command, _ in expected])
        ssh = self.calls("ssh")
        self.assertEqual([call["stdin"] for call in ssh], [stdin for _, _, stdin in expected])
        self.assertEqual([call["argv"] for call in ssh],
                         [self.admin_argv(command, terminal=flag == "-t") for flag, command, _ in expected])
        # The token is asked after the first two commands and only once.
        self.assertEqual([call["tool"] for call in self.calls()],
                         ["ssh", "ssh", "fido2-token", "fido2-assert"] + ["ssh"] * 9)
        self.assertEqual(ssh[4]["wrote"], [[key, 0o600]])
        self.assertEqual(self.server_files(), {})
        for device in ("/dev/sda3", "/dev/sdb3"):
            self.assertEqual(self.keyslots(device), [INSTALLATION_KEY, SECRET])
        self.assertEqual(lines, [
            ASKING,
            checking("/dev/sda3"), NO_KEY, checking("/dev/sdb3"), NO_KEY,
            "kaltstart: /dev/sda3: none yet, adding a keyslot", PROMPT,
            "kaltstart: /dev/sda3: added", "kaltstart: /dev/sda3: verified (keyslot 1)",
            "kaltstart: /dev/sdb3: none yet, adding a keyslot", PROMPT,
            "kaltstart: /dev/sdb3: added", "kaltstart: /dev/sdb3: verified (keyslot 1)",
            "kaltstart: enrollment complete for 2 device(s); the key file was removed from the server"])

    def test_secret_never_leaves_the_stdin_pipes(self):
        self.write_host(port=2222, device=None, extra="devices = /dev/sda3")
        result = self.run_cli("-v", "enroll", "srv", env={"STUB_SSH_ECHO_STDIN": "1", "STUB_SSH_ECHO_STDIN_ERR": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls()), 9)
        self.assertEqual(result.stderr.count(b"kaltstart: run: "), 9)
        self.assertEqual([call["stdin"] for call in self.calls("ssh")], [b"", SECRET, SECRET, b"", b"", SECRET, b""])
        # A server that repeats what it receives: the upload on both streams, the tests on standard error.
        self.assertEqual(result.stderr.count(b"kaltstart: ssh: [passphrase removed]"), 3)
        self.assertEqual(result.stderr.count(b"kaltstart: remote: [passphrase removed]"), 1)
        self.assertNotIn(SECRET, result.stderr + result.stdout)
        self.assert_no_trace_of(SECRET)

    def test_repeated_run_adds_nothing(self):
        self.assertEqual(self.enroll()[0], 0)
        status, lines, commands = self.enroll()
        self.assertEqual(status, 0, lines)
        # Nothing is uploaded, added or removed: a second keyslot with the same passphrase would be of no use.
        self.assertEqual(commands, ["cryptsetup isLuks /dev/sda3", TEST + "/dev/sda3"])
        self.assertEqual(lines, [ASKING, checking("/dev/sda3"), "kaltstart: /dev/sda3: already enrolled (keyslot 1)",
                                 "kaltstart: enrollment complete for 1 device(s)"])
        self.assertEqual(self.keyslots("/dev/sda3"), [INSTALLATION_KEY, SECRET])

    def test_partly_enrolled_devices_are_completed(self):
        self.add_keyslot("/dev/sda3", b"some other passphrase")
        self.add_keyslot("/dev/sda3", SECRET)
        status, lines, commands = self.enroll("--device-on-server", "/dev/sda3", "--device-on-server", "/dev/sdb3")
        self.assertEqual(status, 0, lines)
        key = self.key_file(commands)
        self.assertEqual(commands[4:], [f"umask 077 && cat > {key}", f"sha256sum {key}",
                                        f"cryptsetup luksAddKey --new-keyfile {key} /dev/sdb3", TEST + "/dev/sdb3",
                                        f"rm -f {key}"])
        self.assertEqual(lines[1:], [
            checking("/dev/sda3"), "kaltstart: /dev/sda3: already enrolled (keyslot 2)", checking("/dev/sdb3"), NO_KEY,
            "kaltstart: /dev/sdb3: none yet, adding a keyslot", PROMPT, "kaltstart: /dev/sdb3: added",
            "kaltstart: /dev/sdb3: verified (keyslot 1)",
            "kaltstart: enrollment complete for 2 device(s); the key file was removed from the server"])
        self.assertEqual(len(self.keyslots("/dev/sda3")), 3)

    def test_token_and_device_options(self):
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\ndevice = /dev/hidraw5\n"
                          f"[token spare]\ncredential_id = {OTHER_CRED_ID}\ndevice = /dev/hidraw6\n"
                          f"[host srv]\nhost = 127.0.0.1\nsalt = {SALT}\ntoken = main\ndevices = /dev/sda3\n")
        # The options may precede the host; a device option replaces the devices of the configuration.
        result = self.run_cli("enroll", "--token", "spare", "--device", "/dev/hidraw8", "--device-on-server", "/dev/sdb3",
                              "srv")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("fido2-assert")[0]["argv"][-1], "/dev/hidraw8")
        self.assertEqual(self.keyslots("/dev/sdb3"), [INSTALLATION_KEY, expected_secret(credential_id=OTHER_CRED_ID)])
        self.assertEqual(self.keyslots("/dev/sda3"), [INSTALLATION_KEY])
        # One device per option: a second value is not taken for a device (nor for the host).
        result = self.run_cli("enroll", "srv", "--device-on-server", "/dev/sda3", "/dev/sdb3")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"unrecognized arguments: /dev/sdb3", result.stderr)

    # ----------------------------------------------- before the token is used

    def test_unreachable_server_is_reported_before_the_token_is_used(self):
        for status in ("255", "-9"):  # ssh fails, or is ended by a signal
            with self.subTest(status=status):
                code, lines, commands = self.enroll(env={"STUB_SSH_FAIL_MATCH": "isLuks", "STUB_SSH_FAIL_RC": status})
                self.assertEqual(code, 4)
                self.assertEqual(lines[-1], f"kaltstart: ssh to admin.example.net failed (exit status {status})")
                self.assertEqual(commands, ["cryptsetup isLuks /dev/sda3"])
        self.assertEqual(self.calls("fido2-assert"), [])  # PIN and touch were not spent

    def test_unusable_device_is_reported_before_the_token_is_used(self):
        code, lines, commands = self.enroll("--device-on-server", "/dev/sda3", "--device-on-server", "/dev/sdc1")
        self.assertEqual(code, 5)
        self.assertEqual(lines, ["kaltstart: /dev/sdc1 cannot be used on admin.example.net: it is not a LUKS device, or "
                                 "the command could not be run as root (exit status 1)"])
        self.assertEqual(commands, ["cryptsetup isLuks /dev/sda3", "cryptsetup isLuks /dev/sdc1"])
        self.assertEqual(self.calls("fido2-assert"), [])

    def test_missing_root_rights_are_reported_before_the_token_is_used(self):
        problem = ("kaltstart: /dev/sda3 cannot be used on 127.0.0.1: it is not a LUKS device, or the command could not "
                   "be run as root (exit status {})")
        self.write_host(port=2222, extra="admin_user = ops\ndevices = /dev/sda3")
        code, lines, commands = self.enroll()
        self.assertEqual((code, lines[-1], commands), (5, problem.format(4), ["cryptsetup isLuks /dev/sda3"]))
        # sudo without a terminal must not ask: it would wait for a password that nobody can type.
        self.write_host(port=2222, extra="admin_user = ops\nadmin_sudo = yes\ndevices = /dev/sda3")
        code, lines, commands = self.enroll(env={"STUB_SSH_SUDO_PASSWORD": "1"})
        self.assertEqual((code, commands), (5, ["sudo -n cryptsetup isLuks /dev/sda3"]))
        self.assertEqual(lines, ["kaltstart: ssh: sudo: a password is required", problem.format(1)])
        self.assertEqual(self.calls("fido2-assert"), [])

    def test_no_devices_lists_them_and_touches_nothing(self):
        self.write_host(port=2222)
        code, lines, _ = self.enroll()
        self.assertEqual(code, 2)
        (call,) = self.calls()
        # Without admin_port the port is left to the ssh configuration of the user.
        self.assertEqual(call["argv"], ["-T"] + FORCED + DEFAULTS + ["--", "root@127.0.0.1",
                                                                     "blkid -t TYPE=crypto_LUKS -o device"])
        self.assertEqual(lines, ["kaltstart: LUKS devices on 127.0.0.1:", "kaltstart: remote: /dev/sda3",
                                 "kaltstart: remote: /dev/sdb3", "kaltstart: no LUKS devices configured; set 'devices' "
                                 "in [host srv] or pass --device-on-server"])
        code, lines, _ = self.enroll(env={"STUB_SSH_STDOUT": "/dev/evil\x1b[2J\n"})
        self.assertEqual((code, lines[1]), (2, "kaltstart: remote: /dev/evil\\x1b[2J"))
        code, lines, _ = self.enroll(env={"STUB_SSH_FAIL_MATCH": "blkid", "STUB_SSH_FAIL_RC": "255"})
        self.assertEqual((code, lines[-1]), (4, "kaltstart: ssh to 127.0.0.1 failed (exit status 255)"))
        self.assertEqual([call["tool"] for call in self.calls()], ["ssh"] * 3)

    def test_token_failure_changes_nothing_on_the_server(self):
        code, lines, commands = self.enroll(env={"STUB_ASSERT_MODE": "garbage"})
        self.assertEqual((code, lines[-1]), (3, "kaltstart: the token returned no usable hmac-secret value"))
        self.assertEqual(commands, ["cryptsetup isLuks /dev/sda3"])
        self.assertEqual((self.keyslots("/dev/sda3"), self.server_files()), ([INSTALLATION_KEY], {}))

    def test_missing_programs_are_reported_before_the_server_is_contacted(self):
        self.remove_stub("fido2-assert")
        self.assertEqual(self.enroll(), (3, ["kaltstart: fido2-assert not found in PATH (install fido2-tools)"], []))
        self.remove_stub("ssh")
        self.assertEqual(self.enroll(), (4, ["kaltstart: ssh not found in PATH"], []))

    def test_missing_fido2_token_is_reported_before_the_server_is_contacted(self):
        # Without a configured device the token has to be found, which needs fido2-token.
        self.write_host(port=2222, device=None, extra="devices = /dev/sda3")
        self.remove_stub("fido2-token")
        self.assertEqual(self.enroll(), (3, ["kaltstart: fido2-token not found in PATH (install fido2-tools)"], []))
        self.assertEqual(self.enroll("--device", "/dev/hidraw5")[0], 0)

    def test_hostile_server_paths_are_rejected(self):
        absolute = "must be an absolute path on the server"
        for arguments, option in ((["--device-on-server", "sda3"], "--device-on-server"),
                                  (["--device-on-server", "/dev/sda3\n/dev/sdb3"], "--device-on-server"),
                                  (["--device-on-server=-x"], "--device-on-server"),
                                  (["--existing-keyfile", "relative/key"], "--existing-keyfile"),
                                  (["--existing-keyfile", "/root/key\x1b"], "--existing-keyfile")):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.enroll(*arguments), (2, [f"kaltstart: {option}: {absolute}"], []))
        self.assertEqual(self.calls(), [])

    # ------------------------------------------------- the test of step 3

    def test_failing_check_adds_nothing(self):
        # Anything but "no keyslot opens" (exit status 2) is an error; its output is shown.
        env = {"STUB_SSH_FAIL_MATCH": "--test-passphrase", "STUB_SSH_STDOUT": "evil \x1b[2J output\n"}
        for status, code in (("1", 5), ("255", 4), ("-9", 4)):
            with self.subTest(status=status):
                result, lines, commands = self.enroll(env=dict(env, STUB_SSH_FAIL_RC=status))
                self.assertEqual(result, code)
                self.assertEqual(commands, ["cryptsetup isLuks /dev/sda3", TEST + "/dev/sda3"])
                self.assertEqual(lines[-3:], ["kaltstart: remote: evil \\x1b[2J output",
                                              f"kaltstart: /dev/sda3: failed (the check ended with exit status {status})",
                                              "kaltstart: enrollment failed for: /dev/sda3"])
        self.assertEqual((self.keyslots("/dev/sda3"), self.server_files()), ([INSTALLATION_KEY], {}))

    def test_failing_check_of_one_device_leaves_the_others_their_turn(self):
        code, lines, commands = self.enroll("--device-on-server", "/dev/sda3", "--device-on-server", "/dev/sdb3",
                                            env={"STUB_SSH_FAIL_MATCH": "--key-file - /dev/sda3"})
        self.assertEqual(code, 5)
        key = self.key_file(commands)
        self.assertEqual(commands[2:], [TEST + "/dev/sda3", TEST + "/dev/sdb3", f"umask 077 && cat > {key}",
                                        f"sha256sum {key}", f"cryptsetup luksAddKey --new-keyfile {key} /dev/sdb3",
                                        TEST + "/dev/sdb3", f"rm -f {key}"])
        self.assertIn("kaltstart: /dev/sda3: failed (the check ended with exit status 1)", lines)
        self.assertEqual(lines[-2:], ["kaltstart: /dev/sdb3: verified (keyslot 1)",
                                      "kaltstart: enrollment failed for: /dev/sda3"])
        self.assertEqual((self.keyslots("/dev/sda3"), self.keyslots("/dev/sdb3")),
                         ([INSTALLATION_KEY], [INSTALLATION_KEY, SECRET]))

    # ---------------------------------------------------------- the key file

    def test_failed_upload_still_removes_the_file(self):
        for status in ("255", "1"):
            with self.subTest(status=status):
                code, lines, commands = self.enroll(env={"STUB_SSH_FAIL_MATCH": "cat >", "STUB_SSH_FAIL_RC": status})
                self.assertEqual(code, 4)
                key = self.key_file(commands)  # the file may exist in part
                self.assertEqual(commands[2:], [f"umask 077 && cat > {key}", f"rm -f {key}"])
                self.assertEqual(lines[-1], "kaltstart: uploading the key file to admin.example.net failed "
                                            f"(ssh exit status {status})")
                self.assertFalse([line for line in lines if "WARNING" in line])

    def test_failed_upload_and_failed_removal(self):
        # Every command that names the key file fails: whether the file exists is not known.
        code, lines, commands = self.enroll(env={"STUB_SSH_FAIL_MATCH": "/run/kaltstart-enroll-",
                                                 "STUB_SSH_FAIL_RC": "255"})
        self.assertEqual(code, 4)
        key = self.key_file(commands)
        self.assertEqual(len(commands), 4)
        self.assertEqual(lines[-2:], [
            f"kaltstart: WARNING: could not make sure that {key} does not exist on admin.example.net. If it exists, it "
            f"contains the LUKS passphrase. Check by hand: rm -f {key}",
            "kaltstart: uploading the key file to admin.example.net failed (ssh exit status 255)"])

    def test_key_file_that_differs_from_what_was_sent_is_not_used(self):
        mismatch = ("kaltstart: the key file on admin.example.net does not hold the passphrase that was sent; "
                    "no keyslot was added")
        for env in ({"STUB_SSH_TRUNCATE_UPLOAD": "43"}, {"STUB_SSH_TRUNCATE_UPLOAD": "0"},
                    {"STUB_SSH_FAIL_MATCH": "sha256sum"}, {"STUB_SSH_FAIL_MATCH": "sha256sum", "STUB_SSH_FAIL_RC": "255"}):
            with self.subTest(env=env):
                code, lines, commands = self.enroll(env=env)
                self.assertEqual((code, lines[-1]), (4, mismatch))
                key = self.key_file(commands)
                self.assertEqual(commands[2:], [f"umask 077 && cat > {key}", f"sha256sum {key}", f"rm -f {key}"])
        self.assertEqual((self.keyslots("/dev/sda3"), self.server_files()), ([INSTALLATION_KEY], {}))

    def test_failed_removal_is_loud(self):
        for status, device in (("255", "/dev/sda3"), ("1", "/dev/sdb3")):
            with self.subTest(status=status):
                code, lines, commands = self.enroll("--device-on-server", device,
                                                    env={"STUB_SSH_FAIL_MATCH": "rm -f", "STUB_SSH_FAIL_RC": status})
                self.assertEqual(code, 4)  # although the keyslot was added and verified
                key = self.key_file(commands)
                self.assertEqual([line for line in lines if not line.startswith("kaltstart: ssh: ")][-3:], [
                    f"kaltstart: {device}: verified (keyslot 1)",
                    f"kaltstart: WARNING: COULD NOT REMOVE {key} ON admin.example.net. IT CONTAINS THE LUKS PASSPHRASE. "
                    f"Remove it by hand: rm -f {key}",
                    "kaltstart: the key file may still be on the server"])
                self.assertEqual(self.server_files().pop(key), (SECRET, 0o600))  # the warning is true

    def test_failed_removal_after_a_failed_device(self):
        # The upload and its check work; luksAddKey and the removal fail.
        code, lines, commands = self.enroll(env={"STUB_SSH_FAIL_MATCH": "/run/kaltstart-enroll-", "STUB_SSH_FAIL_SKIP": "2",
                                                 "STUB_SSH_FAIL_RC": "2"})
        self.assertEqual(code, 4)
        self.assertEqual(len(commands), 6)
        self.assertIn(f"kaltstart: WARNING: COULD NOT REMOVE {self.key_file(commands)} ON admin.example.net.", lines[-2])
        self.assertEqual(lines[-1], "kaltstart: the key file may still be on the server; enrollment failed for: /dev/sda3")

    def test_closed_standard_error_does_not_stop_the_removal(self):
        # "kaltstart -v enroll ... 2>&1 | head": the reader goes away, the key file must not stay.
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = self.run_cli("-v", "enroll", "srv", stderr=writer)
        finally:
            os.close(writer)
        commands = [command for _, command in self.remote_commands()]
        key = self.key_file(commands)
        self.assertEqual(commands[2:], [f"umask 077 && cat > {key}", f"sha256sum {key}",
                                        f"cryptsetup luksAddKey --new-keyfile {key} /dev/sda3", f"rm -f {key}"])
        self.assertEqual(self.server_files(), {})
        # ssh with the terminal could not print the prompt of cryptsetup and was ended before a keyslot was added.
        self.assertEqual(self.keyslots("/dev/sda3"), [INSTALLATION_KEY])
        # The exit status is left open: the interpreter reports the lost messages with a status of its own.
        self.assertNotEqual(result.returncode, 0)

    # ------------------------------------------------------------ luksAddKey

    def test_remote_file_is_removed_when_luksaddkey_fails(self):
        for status, code in (("2", 5), ("255", 4), ("-9", 4)):  # for example a mistyped passphrase; a lost connection
            with self.subTest(status=status):
                result, lines, commands = self.enroll("--device-on-server", "/dev/sda3", "--device-on-server", "/dev/sdb3",
                                                      env={"STUB_SSH_FAIL_MATCH": "luksAddKey", "STUB_SSH_FAIL_RC": status})
                self.assertEqual(result, code)
                key = self.key_file(commands)
                # Every device gets its turn, and a keyslot that was not added is not verified.
                self.assertEqual(commands[6:], [f"cryptsetup luksAddKey --new-keyfile {key} /dev/sda3",
                                                f"cryptsetup luksAddKey --new-keyfile {key} /dev/sdb3", f"rm -f {key}"])
                # (The session with the terminal is not filtered: what ssh prints there is left out here.)
                self.assertEqual([line for line in lines if line.startswith("kaltstart: ")][-4:], [
                    f"kaltstart: /dev/sda3: failed (luksAddKey exit status {status})",
                    "kaltstart: /dev/sdb3: none yet, adding a keyslot",
                    f"kaltstart: /dev/sdb3: failed (luksAddKey exit status {status})",
                    "kaltstart: enrollment failed for: /dev/sda3, /dev/sdb3"])
        self.assertEqual(self.server_files(), {})

    def failed_verification(self, status):
        # The first test of the passphrase runs, the one after luksAddKey fails.
        code, lines, commands = self.enroll(env={"STUB_SSH_FAIL_MATCH": "--test-passphrase", "STUB_SSH_FAIL_SKIP": "1",
                                                 "STUB_SSH_FAIL_RC": status})
        self.assertEqual(len(commands), 7)
        self.key_file(commands)
        self.assertIn("kaltstart: /dev/sda3: added", lines)
        self.assertEqual(lines[-2:], [f"kaltstart: /dev/sda3: failed (verification exit status {status})",
                                      "kaltstart: enrollment failed for: /dev/sda3"])
        self.assertEqual(self.server_files(), {})
        return code

    def test_failed_verification_is_exit_5(self):
        self.assertEqual(self.failed_verification("2"), 5)

    def test_verification_that_cannot_be_run_is_exit_4(self):
        self.assertEqual(self.failed_verification("255"), 4)

    def test_existing_keyfile_needs_neither_a_terminal_nor_a_file(self):
        device = "/dev/disk/by-id/a disk;id"  # a name that the remote shell must not take apart
        self.add_device(device)
        self.add_file("/root/old key", INSTALLATION_KEY)
        code, lines, _ = self.enroll("--existing-keyfile", "/root/old key", "--device-on-server", device)
        self.assertEqual(code, 0, lines)
        quoted = "'/dev/disk/by-id/a disk;id'"
        expected = [("-T", f"cryptsetup isLuks {quoted}", b""),
                    ("-T", TEST + quoted, SECRET),
                    ("-T", f"cryptsetup luksAddKey --key-file '/root/old key' --new-keyfile - {quoted}", SECRET),
                    ("-T", TEST + quoted, SECRET)]
        self.assertEqual(self.remote_commands(), [(flag, command) for flag, command, _ in expected])
        self.assertEqual([call["stdin"] for call in self.calls("ssh")], [stdin for _, _, stdin in expected])
        self.assertEqual(lines[-3:], [f"kaltstart: {device}: added", f"kaltstart: {device}: verified (keyslot 1)",
                                      "kaltstart: enrollment complete for 1 device(s)"])
        self.assertEqual(self.keyslots(device), [INSTALLATION_KEY, SECRET])
        self.assertEqual(self.server_files(), {"/root/old key": (INSTALLATION_KEY, 0o600)})

    def test_device_names_are_quoted_in_every_remote_command(self):
        device = "/dev/disk/by-id/it's a $(disk)"
        self.add_device(device)
        code, lines, commands = self.enroll("--device-on-server", device)
        self.assertEqual(code, 0, lines)
        key, quoted = self.key_file(commands), shlex.quote(device)
        self.assertEqual(commands, [f"cryptsetup isLuks {quoted}", TEST + quoted, f"umask 077 && cat > {key}",
                                    f"sha256sum {key}", f"cryptsetup luksAddKey --new-keyfile {key} {quoted}",
                                    TEST + quoted, f"rm -f {key}"])
        self.assertEqual(self.keyslots(device), [INSTALLATION_KEY, SECRET])

    def test_existing_keyfile_that_opens_no_keyslot(self):
        self.add_file("/root/wrong.key", b"not a passphrase of this device")
        for name, status in (("/root/wrong.key", 2), ("/root/absent.key", 1)):
            with self.subTest(keyfile=name):
                code, lines, commands = self.enroll("--existing-keyfile", name)
                self.assertEqual(code, 5)
                self.assertEqual(commands[2:], [f"cryptsetup luksAddKey --key-file {name} --new-keyfile - /dev/sda3"])
                self.assertEqual(lines[-2:], [f"kaltstart: /dev/sda3: failed (luksAddKey exit status {status})",
                                              "kaltstart: enrollment failed for: /dev/sda3"])
        self.assertEqual(self.keyslots("/dev/sda3"), [INSTALLATION_KEY])

    # ------------------------------------------------------------------ sudo

    def test_admin_sudo_prefixes_every_remote_command(self):
        # Root login over ssh is disabled on the server: log in as a user and use sudo.
        self.write_host(port=2222, extra="admin_user = ops\nadmin_sudo = yes\ndevices = /dev/sda3")
        code, lines, commands = self.enroll()
        self.assertEqual(code, 0, lines)
        key = self.key_file(commands)
        self.assertEqual(self.remote_commands(), [
            ("-T", "sudo -n cryptsetup isLuks /dev/sda3"),
            ("-T", "sudo -n " + TEST + "/dev/sda3"),
            ("-T", f"sudo -n sh -c 'umask 077 && cat > {key}'"),  # the redirection needs root as well
            ("-T", f"sudo -n sha256sum {key}"),
            ("-t", f"sudo cryptsetup luksAddKey --new-keyfile {key} /dev/sda3"),  # may ask on the terminal
            ("-T", "sudo -n " + TEST + "/dev/sda3"),
            ("-T", f"sudo -n rm -f {key}")])
        self.assertEqual({call["destination"] for call in self.calls("ssh")}, {"ops@127.0.0.1"})
        self.assertEqual(self.calls("ssh")[4]["argv"][:3], ["-t", "-e", "none"])
        self.assertEqual((self.keyslots("/dev/sda3"), self.server_files()), ([INSTALLATION_KEY, SECRET], {}))

    def test_admin_sudo_without_a_terminal_never_asks(self):
        self.write_host(port=2222, extra="admin_user = ops\nadmin_sudo = yes")
        code, lines, _ = self.enroll()
        self.assertEqual((code, lines[1:3]), (2, ["kaltstart: remote: /dev/sda3", "kaltstart: remote: /dev/sdb3"]))
        self.assertEqual(self.remote_commands(), [("-T", "sudo -n blkid -t TYPE=crypto_LUKS -o device")])
        self.write_host(port=2222, extra="admin_user = ops\nadmin_sudo = yes\ndevices = /dev/sda3")
        self.add_file("/root/old.key", INSTALLATION_KEY)
        code, lines, commands = self.enroll("--existing-keyfile", "/root/old.key")
        self.assertEqual(code, 0, lines)
        self.assertEqual(commands[2], "sudo -n cryptsetup luksAddKey --key-file /root/old.key --new-keyfile - /dev/sda3")
        self.assertFalse([call for call in self.calls("ssh") if call["terminal"]])

    # --------------------------------------------------------------- signals

    def test_remote_file_is_removed_on_sigterm_and_sighup(self):
        for number, name in enumerate(("SIGTERM", "SIGHUP"), start=1):
            with self.subTest(signal=name):
                seen = len(self.calls("ssh"))
                proc = self.start_cli("enroll", "srv", ignored=(), env={"STUB_SSH_HANG_MATCH": "luksAddKey"})
                call = self.wait_for_call(proc, "ssh", "luksAddKey", start=seen)
                proc.send_signal(getattr(signal, name))
                status, stderr = self.finish(proc)
                self.assertEqual(status, 130, stderr)
                self.assertEqual(stderr.decode().splitlines()[-1], "kaltstart: interrupted")
                self.assert_ended_by_the_program(call)
                commands = [command for _, command in self.remote_commands()]
                self.key_file(commands)
                self.assertEqual(len([command for command in commands if command.startswith("rm -f ")]), number)
                self.assertEqual((self.keyslots("/dev/sda3"), self.server_files()), ([INSTALLATION_KEY], {}))

    def test_sigterm_during_the_upload_ends_ssh_and_removes_the_file(self):
        proc = self.start_cli("enroll", "srv", ignored=(), env={"STUB_SSH_HANG_MATCH": "cat >"})
        call = self.wait_for_call(proc, "ssh", "cat >")
        proc.send_signal(signal.SIGTERM)
        status, stderr = self.finish(proc)
        self.assertEqual(status, 130, stderr)
        # ssh does not go on to write the passphrase to the server after the program has given up.
        self.assert_ended_by_the_program(call)
        commands = [command for _, command in self.remote_commands()]
        key = self.key_file(commands)  # the removal runs: the file may exist already
        self.assertEqual(commands[2:], [f"umask 077 && cat > {key}", f"rm -f {key}"])
        self.assertEqual(stderr.decode().splitlines()[-1], "kaltstart: interrupted")
        self.assertNotIn(b"WARNING", stderr)

    def test_removal_ignores_sigint_sigterm_sighup_and_sigquit(self):
        # A second Ctrl-C, or a hangup, must not end the removal of the key file.
        proc = self.start_cli("enroll", "srv", ignored=(), env={"STUB_SSH_HANG_MATCH": "rm -f"})
        call = self.wait_for_call(proc, "ssh", "rm -f")
        self.assertEqual(call["ignored"], sorted(SIGNAL_NAMES))
        for name in SIGNAL_NAMES:
            proc.send_signal(getattr(signal, name))
        self.release()
        status, stderr = self.finish(proc)
        self.assertEqual(status, 0, stderr)
        self.assertEqual(stderr.decode().splitlines()[-1],
                         "kaltstart: enrollment complete for 1 device(s); the key file was removed from the server")
        self.assertEqual(self.server_files(), {})
        # Before the removal the signals had their effect, and ssh was started accordingly.
        self.assertEqual([call["ignored"] for call in self.calls("ssh")[:-1]], [[]] * 6)


class CleanupTests(IsolatedTestCase):
    def test_signals_are_ignored_for_the_block_only(self):
        before = [signal.getsignal(signum) for signum in cli.TERMINATION_SIGNALS]
        for signum, handler in zip(cli.TERMINATION_SIGNALS, before):
            self.addCleanup(signal.signal, signum, handler)
        with self.assertRaises(RuntimeError), cli.signals_ignored():
            self.assertEqual([signal.getsignal(signum) for signum in cli.TERMINATION_SIGNALS], [signal.SIG_IGN] * 4)
            raise RuntimeError("the removal failed")
        self.assertEqual([signal.getsignal(signum) for signum in cli.TERMINATION_SIGNALS], before)
