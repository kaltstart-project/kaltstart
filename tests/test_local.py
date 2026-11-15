# SPDX-License-Identifier: GPL-2.0-only
"""Tests for everything that stays on the workstation: configuration, token, init, add-host, derive, check, list."""

import argparse
import base64
import configparser
import contextlib
import errno
import io
import os
import pty
import resource
import shlex
import shutil
import signal
import socket
import stat
import types
from unittest import mock

from support import (CALLER_PATH, CLI, CRED_ID, DEVICE_LINE, OTHER_CRED_ID, OTHER_SALT, SALT, STUB_CRED_ID,
                     CliTestCase, IsolatedTestCase, cli, expected_secret)

SECOND_DEVICE = "/dev/hidraw7: vendor=0x1234, product=0x9abc (Another FIDO2 Token)\n"
# Decodes to the same 32 bytes as SALT, but the unused bits of its last character are not zero.
NON_CANONICAL = SALT[:-2] + "9="


def captured_stderr():
    return contextlib.redirect_stderr(io.StringIO())


class ConfigUnitTests(IsolatedTestCase):
    def test_host_defaults(self):
        host = cli.parse_host("srv", {"host": "srv01.example.net", "salt": SALT, "port": "  "})
        self.assertEqual((host.port, host.user, host.remote_command, host.prompts), (22, "root", "cryptroot-unlock", 1))
        self.assertEqual((host.admin_host, host.admin_port, host.admin_user), ("srv01.example.net", None, "root"))
        self.assertEqual((host.identity, host.known_hosts, host.token, host.booted_port), (None, None, None, None))
        self.assertEqual((host.ssh_options, host.admin_ssh_options, host.devices), ([], [], []))
        self.assertIs(host.probe, True)
        self.assertIs(host.admin_sudo, False)
        for name in ("srv01.example.net.", "x" * 63 + ".example.net", "::ffff:203.0.113.1", "2001:db8::1", "203.0.113.7"):
            self.assertEqual(cli.parse_host("srv", {"host": name, "salt": SALT}).host, name)

    def test_host_all_keys(self):
        host = cli.parse_host("srv", {
            "host": "2001:db8::1", "port": "2222", "user": "unlock", "identity": "~/.ssh/id_unlock",
            "known_hosts": "/etc/kh", "salt": SALT, "token": "main", "remote_command": "cryptroot-unlock",
            "prompts": "2", "booted_port": "22", "probe": "no",
            "ssh_options": "-o ConnectTimeout=5 -o 'ProxyCommand=ssh -W %h:%p jump.example.net'",
            "admin_host": "admin.example.net", "admin_port": "2200", "admin_user": "ops", "admin_sudo": "yes",
            "admin_ssh_options": "-4", "devices": "/dev/sda3, /dev/nvme0n1p3\n/dev/sdb1"})
        self.assertEqual(host.identity, "/nonexistent/home/.ssh/id_unlock")  # "~" is HOME, which the test case sets
        self.assertEqual(host.known_hosts, "/etc/kh")
        self.assertEqual(host.ssh_options, ["-o", "ConnectTimeout=5", "-o", "ProxyCommand=ssh -W %h:%p jump.example.net"])
        self.assertEqual(host.admin_ssh_options, ["-4"])
        self.assertEqual(host.devices, ["/dev/sda3", "/dev/nvme0n1p3", "/dev/sdb1"])
        self.assertEqual((host.host, host.user, host.token), ("2001:db8::1", "unlock", "main"))
        self.assertEqual((host.port, host.prompts, host.booted_port, host.admin_port), (2222, 2, 22, 2200))
        self.assertEqual((host.admin_host, host.admin_user), ("admin.example.net", "ops"))
        self.assertIs(host.probe, False)
        self.assertIs(host.admin_sudo, True)

    def test_host_validation_errors_name_section_and_key(self):
        short_salt, long_salt = (base64.b64encode(b"x" * length).decode() for length in (16, 33))
        missing, name = "required key is missing", "invalid host name or address"
        label = "invalid host name (empty label or label longer than 63 characters)"
        port, user = "must be an integer between 1 and 65535", "invalid user name"
        unsafe, relative = "path must not contain white space", "must be an absolute path, or start with '~'"
        cases = {
            "host": [(None, missing), ("-oProxyCommand=evil", name), ("srv01 example.net", name),
                     ("srv01.example.net;id", name), ("$(id).example.net", name), ("user@srv01.example.net", name),
                     ("srv01.example.net/x", name), ("srv01..example.net", label), ("example.net..", label),
                     ("x" * 64 + ".example.net", label), ("example." + "x" * 64, label)],
            "port": [("0", port), ("65536", port), ("-1", port), ("ssh", port), ("22 23", port)],
            "user": [("-lroot", user), ("root;id", user), ("a b", user), ("root@srv01.example.net", user)],
            "salt": [(None, missing), (short_salt, "must be base64 of exactly 32 bytes (got 16)"),
                     ("not base64", "not valid base64"), (SALT[:-1], "not valid base64"),
                     (long_salt, "must be base64 of exactly 32 bytes (got 33)"), (SALT + "AAAA", "not valid base64"),
                     (NON_CANONICAL, "not valid base64")],
            "prompts": [(value, "must be an integer between 1 and 1000") for value in ("0", "-1", "two", "1001")],
            "booted_port": [("0", port), ("70000", port)],
            "probe": [("maybe", "must be yes or no"), ("2", "must be yes or no")],
            "admin_sudo": [("maybe", "must be yes or no")],
            "admin_port": [("99999", port)],
            "admin_host": [("-evil", name)],
            "admin_user": [("-evil", user)],
            "token": [("bad name", "invalid name"), ("-x", "invalid name")],
            "ssh_options": [("-o 'unterminated", "cannot be split into arguments")],
            "identity": [("/path with blank/id", unsafe), ("/tmp/%h", unsafe), ("/keys/id#1", unsafe), ("/keys/'id'", unsafe),
                         ("keys/id", relative), ("./id", relative)],
            "known_hosts": [("/a b", unsafe), ("kh", relative)],
            "devices": [("sda3", "must be an absolute path on the server"),
                        ("/dev/sda3 -x", "must be an absolute path on the server"),
                        ("/dev/sd\x07a", "must be an absolute path on the server")],
            "remote_command": [("-x", "must be a non-empty single-line value")],
        }
        for key, values in cases.items():
            for value, problem in values:
                raw = {"host": "srv01.example.net", "salt": SALT}
                if value is None:
                    del raw[key]
                else:
                    raw[key] = value
                # The message starts with the section and the key at fault.
                with self.subTest(key=key, value=value), self.assert_failure(2, start=f"[host srv] {key}: {problem}"):
                    cli.parse_host("srv", raw)

    def test_ssh_options_hold_only_options_and_their_arguments(self):
        accepted = ("-J bastion.example.net", "-o ConnectTimeout=7 -4", "-oForwardAgent=yes", "-i '/keys/a key'",
                    "-o -A", "-JA", "-vv -6 -C -q", "-F /keys/ssh.conf -P tag -E /keys/ssh.log -b 203.0.113.5")
        for key in ("ssh_options", "admin_ssh_options"):
            for value in accepted:
                with self.subTest(key=key, value=value):
                    cli.parse_host("srv", {"host": "srv01.example.net", "salt": SALT, key: value})
            # A word that is no option would become the destination, an option
            # without its argument would take the destination as its argument,
            # and a flag would override the forced "-o" options or the keys of
            # the section.
            for value, fragment in (("bastion.example.net", "neither an option"),
                                    ("-4 bastion.example.net", "neither an option"),
                                    ("-- -4", "neither an option"), ("-", "neither an option"),
                                    ("-J", "lacks its argument"), ("-4 -o", "lacks its argument"),
                                    ("-A", "-A is not allowed"), ("-4X", "-X is not allowed"),
                                    ("-J bastion.example.net -Y", "-Y is not allowed"), ("'unbalanced", "cannot be split"),
                                    ("-M", "-M is not allowed: connection sharing"),
                                    ("-S /keys/cm.sock", "-S is not allowed: connection sharing"),
                                    ("-O exit", "-O is not allowed: connection sharing"),
                                    ("-p 2222", "-p is not allowed: the port is set with its own key"),
                                    ("-4l root", "-l is not allowed: the user is set with its own key"),
                                    ("-n", "-n is not allowed: only -4 -6 -C -q -v"),
                                    ("-W 203.0.113.5:22", "-W is not allowed: only -4 -6 -C -q -v"),
                                    ("-4 'evil\x1b[2J'", "'evil\\x1b[2J' is neither an option")):
                raw = {"host": "srv01.example.net", "salt": SALT, key: value}
                with self.subTest(key=key, value=value), self.assert_failure(2, f"[host srv] {key}: ", fragment):
                    cli.parse_host("srv", raw)

    def test_unknown_key_is_rejected(self):
        with self.assert_failure(2, "[host srv] prot: unknown key"):
            cli.parse_host("srv", {"host": "srv01.example.net", "salt": SALT, "prot": "22"})
        with self.assert_failure(2, "[token main] pim: unknown key"):
            cli.parse_token("main", {"credential_id": CRED_ID, "pim": "yes"})
        with self.assert_failure(2, "[token main] \\x1b[2Jpin: unknown key"):
            cli.parse_token("main", {"credential_id": CRED_ID, "\x1b[2Jpin": "yes"})

    def test_token_parsing(self):
        token = cli.parse_token("main", {"credential_id": CRED_ID})
        self.assertEqual((token.name, token.rp_id, token.pin, token.device), ("main", "kaltstart", True, None))
        token = cli.parse_token("main", {"credential_id": CRED_ID, "pin": "No", "rp_id": "example.net",
                                         "device": "/dev/hidraw1"})
        self.assertEqual((token.rp_id, token.pin, token.device), ("example.net", False, "/dev/hidraw1"))
        for key, value, problem in (("credential_id", None, "required key is missing"),
                                    ("credential_id", "###", "not valid base64"),
                                    ("credential_id", NON_CANONICAL, "not valid base64"),
                                    ("pin", "maybe", "must be yes or no"),
                                    ("device", "-x", "must be a non-empty single-line value"),
                                    ("rp_id", "-x", "must be a non-empty single-line value")):
            raw = {"credential_id": CRED_ID}
            if value is None:
                del raw[key]
            else:
                raw[key] = value
            with self.subTest(key=key, value=value), self.assert_failure(2, start=f"[token main] {key}: {problem}"):
                cli.parse_token("main", raw)

    def test_text_values_are_single_lines_without_control_characters(self):
        # These values become a line of the parameter file of fido2-assert, an
        # argument of it, or the remote command: a second line would shift the
        # lines that follow, and C1 control characters act on a terminal like
        # an escape sequence.
        hostile = ("kalt\nstart", "kalt\rstart", "kalt\x00start", "kalt\x1bstart", "kalt\x7fstart", "kalt\x85start",
                   "kalt\x9bstart")
        for value in hostile:
            for key in ("rp_id", "device"):
                with self.subTest(key=key, value=value), \
                        self.assert_failure(2, f"[token main] {key}: must be a non-empty single-line value"):
                    cli.parse_token("main", {"credential_id": CRED_ID, key: value})
            with self.subTest(key="remote_command", value=value), \
                    self.assert_failure(2, "[host srv] remote_command: must be a non-empty single-line value"):
                cli.parse_host("srv", {"host": "srv01.example.net", "salt": SALT, "remote_command": value})
        token = cli.parse_token("main", {"credential_id": CRED_ID, "rp_id": " b\u00fccher.example.net "})
        self.assertEqual(token.rp_id, "b\u00fccher.example.net")  # white space around a value is not part of it

    def test_hmac_secret_acceptance(self):
        good = base64.b64encode(bytes(range(32)))
        self.assertTrue(cli.is_hmac_secret(good))
        for candidate in (b"", good[:-1], good + b"\n", base64.b64encode(b"x" * 31), base64.b64encode(b"x" * 33),
                          b"!" * 44, good[:-2] + b"==", NON_CANONICAL.encode()):
            with self.subTest(candidate=candidate):
                self.assertFalse(cli.is_hmac_secret(candidate))

    def test_escape_control(self):
        for text, escaped in (("ok \x1b[31m\ttab\x7f", "ok \\x1b[31m\\x09tab\\x7f"),
                              ("two\nlines\r", "two\\x0alines\\x0d"),
                              ("back\\slash \\x1b", "back\\\\slash \\\\x1b"),  # an escaped text cannot be forged
                              ("\x00\x85\x9b\xa0", "\\x00\\x85\\x9b\\xa0"),
                              ("\u202e\u2028\ufeff", "\\u202e\\u2028\\ufeff"),
                              ("\ud800", "\\ud800"),
                              ("\U000e0001\U0010ffff", "\\U000e0001\\U0010ffff"),
                              ("b\u00fccher \u4e2d \U0001f511", "b\u00fccher \u4e2d \U0001f511")):
            with self.subTest(text=text):
                self.assertEqual(cli.escape_control(text), escaped)

    def test_access_problem(self):
        def judge(mode, uid):
            return cli.access_problem(types.SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid))

        owner = os.geteuid()
        self.assertEqual(judge(0o600, owner), (False, None))
        self.assertEqual(judge(0o400, 0), (False, None))  # a file of root is as good as an own one
        self.assertEqual(judge(0o600, owner + 1), (True, "is owned by another user"))
        for mode in (0o620, 0o602, 0o660, 0o666, 0o622, 0o777):
            self.assertEqual(judge(mode, owner), (True, f"is writable by group or others (mode {mode:04o})"))
        for mode in (0o640, 0o604, 0o644, 0o610, 0o601):
            self.assertEqual(judge(mode, owner), (False, f"is accessible by group or others (mode {mode:04o})"))

    def test_default_config_path(self):
        with mock.patch.dict(os.environ, {"HOME": "/home/user"}):
            self.assertEqual(cli.default_config_path(), "/home/user/.config/kaltstart/config.ini")
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": ""}):
                self.assertEqual(cli.default_config_path(), "/home/user/.config/kaltstart/config.ini")
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/etc/xdg-user"}):
                self.assertEqual(cli.default_config_path(), "/etc/xdg-user/kaltstart/config.ini")

    def test_same_machine(self):
        addresses = {"a.example.net": ["203.0.113.5"], "b.example.net": ["2001:db8::5", "203.0.113.5"],
                     "c.example.net": ["203.0.113.6"]}

        def resolve(name, port):
            if name not in addresses:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            return [(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))
                    for address in addresses[name]]

        with mock.patch.object(cli.socket, "getaddrinfo", side_effect=resolve) as lookup:
            # Equal names are the same machine whether or not they resolve.
            self.assertTrue(cli.same_machine("srv01.example.net", "SRV01.Example.NET."))
            self.assertTrue(cli.same_machine("2001:db8::1", "2001:DB8::1"))
            lookup.assert_not_called()
            self.assertTrue(cli.same_machine("a.example.net", "b.example.net"))  # a common address
            self.assertFalse(cli.same_machine("a.example.net", "c.example.net"))
            self.assertFalse(cli.same_machine("a.example.net", "unknown.example.net"))
            self.assertFalse(cli.same_machine("unknown.example.net", "a.example.net"))

    def test_transport_failures_are_255_and_signals(self):
        self.assertEqual([status for status in (255, -1, -9, -15, 0, 1, 2, 4, 127, 254) if cli.transport_failed(status)],
                         [255, -1, -9, -15])

    def test_seconds(self):
        self.assertEqual([cli.seconds(text) for text in ("0", "0.5", "600", "31536000")], [0.0, 0.5, 600.0, 31536000.0])
        for text in ("-1", "-0.5", "nan", "inf", "-inf", "31536001", "1e9"):
            with self.subTest(text=text):
                with self.assertRaises(argparse.ArgumentTypeError) as caught:
                    cli.seconds(text)
                self.assertEqual(str(caught.exception), "must be a number of seconds between 0 and 31536000 (one year)")
        with self.assertRaises(ValueError):
            cli.seconds("soon")


class ConfigFileTests(CliTestCase):
    def test_load_and_token_selection(self):
        self.write_config(f"[token a]\ncredential_id = {CRED_ID}\n[token b]\ncredential_id = {CRED_ID}\npin = no\n"
                          f"[host one]\nhost = a.example.net\nsalt = {SALT}\n"
                          f"[host two]\nhost = b.example.net\nsalt = {SALT}\ntoken = b\n")
        config = cli.load_config(self.config)
        one, two = config.host("one"), config.host("two")
        self.assertEqual(config.token_for(two, None).name, "b")
        self.assertEqual(config.token_for(two, "a").name, "a")
        with self.assert_failure(2, f"[host one] names no token and {self.config} has 2 token sections; "
                                    "set the token key of the host or use --token"):
            config.token_for(one, None)
        with self.assert_failure(2, f"no [token missing] section in {self.config}"):
            config.token_for(one, "missing")
        with self.assert_failure(2, f"no [host three] section in {self.config}"):
            config.host("three")

    def test_single_token_is_the_default(self):
        self.write_host()
        config = cli.load_config(self.config)
        self.assertEqual(config.token_for(config.host("srv"), None).name, "main")

    def test_missing_file_and_missing_sections_are_named(self):
        config = cli.load_config(self.config)
        with self.assert_failure(2, message=f"no [host srv] section in {self.config} (the file does not exist)"):
            config.host("srv")
        result = self.run_cli("derive", "srv")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr.decode(), f"kaltstart: no [host srv] section in {self.config} "
                                                 "(the file does not exist)\n")
        self.write_config(f"[host srv]\nhost = srv01.example.net\nsalt = {SALT}\n")
        config = cli.load_config(self.config)
        with self.assert_failure(2, message=f"no [host other] section in {self.config}"):
            config.host("other")
        with self.assert_failure(2, message=f"no [token ...] section in {self.config}; create one with 'kaltstart init'"):
            config.token_for(config.host("srv"), None)

    def test_broken_files_are_configuration_errors(self):
        unknown = "unknown section (expected [token NAME] or [host NAME])"
        cases = (("[server x]\nhost = srv01.example.net\n", "[server x]: " + unknown),
                 ("[host bad name here]\nhost = srv01.example.net\n", "[host bad name here]: " + unknown),
                 ("[host]\nhost = srv01.example.net\n", "[host]: " + unknown),
                 ("[host -x]\nhost = srv01.example.net\n", "[host -x]: invalid name"),
                 ("[host a]\n[host  a]\n", "[host  a]: section is defined twice"),
                 ("[DEFAULT]\nprompts = 3\n[host a]\nhost = srv01.example.net\n", "[DEFAULT]: " + unknown),
                 ("no section header\n", f"cannot read {self.config}: File contains no section headers"),
                 ("[host a]\nhost = a.example.net\n[host a]\nhost = b.example.net\n", "already exists"),
                 ("[host a]\nhost = a.example.net\nhost = b.example.net\n", "already exists"),
                 ("[host a]\nhost = a.example.net\nsalt = \udcff\n", f"cannot read {self.config}: "))
        for text, fragment in cases:
            os.makedirs(os.path.dirname(self.config), exist_ok=True)
            with open(self.config, "w", encoding="utf-8", errors="surrogateescape") as handle:
                handle.write(text)
            os.chmod(self.config, 0o600)
            # assert_failure also checks that the texts of the parser, which have several lines, became one.
            with self.subTest(text=text), self.assert_failure(2, fragment):
                cli.load_config(self.config)

    def test_default_section_is_rejected(self):
        # configparser would copy its keys into every other section.
        for default in ("[DEFAULT]\nprompts = 3\n", "[DEFAULT]\n"):  # also without keys
            with self.subTest(default=default):
                self.write_config(f"{default}[host srv]\nhost = 127.0.0.1\nsalt = {SALT}\n")
                result = self.run_cli("list")
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"kaltstart: [DEFAULT]: unknown section", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_section_names_and_keys_are_escaped(self):
        for text, fragment in (("[host \x1b[2J x y]\n", "[host \\x1b[2J x y]: unknown section"),
                               ("[host a\x1bb]\n", "[host a\\x1bb]: invalid name"),
                               ("[host a\u202eb]\n", "[host a\\u202eb]: invalid name")):
            self.write_config(text)
            with self.subTest(text=text), self.assert_failure(2, start=fragment):
                cli.load_config(self.config)
        self.write_config(f"[host a]\nhost = srv01.example.net\nsalt = {SALT}\n\x1b[2Jport = 22\n")
        with self.assert_failure(2, "[host a] \\x1b[2jport: unknown key"):
            cli.load_config(self.config).host("a")

    def test_percent_signs_are_not_interpolated(self):
        self.write_config(f"[host a]\nhost = srv01.example.net\nsalt = {SALT}\nremote_command = unlock %(x)s\n")
        self.assertEqual(cli.load_config(self.config).host("a").remote_command, "unlock %(x)s")

    def test_continuation_line_does_not_become_a_second_parameter(self):
        # configparser joins an indented line to the value before it. As a
        # second line of the relying party ID it would take the place of the
        # credential ID in the input of fido2-assert.
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\nrp_id = kaltstart\n  AAAA\n"
                          f"[host srv]\nhost = 127.0.0.1\nsalt = {SALT}\n")
        result = self.run_cli("derive", "srv")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"kaltstart: [token main] rp_id: must be a non-empty single-line value", result.stderr)
        self.assertEqual((result.stdout, self.calls()), (b"", []))

    def test_exit_code_and_message_for_invalid_value(self):
        self.write_host(port=70000)
        result = self.run_cli("unlock", "srv", "--wait", "0")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"kaltstart: [host srv] port: must be an integer between 1 and 65535\n")
        self.assertEqual(self.calls(), [])

    def test_file_that_others_can_write_is_refused(self):
        # Its content decides where the passphrase is sent.
        self.write_host()
        quoted = shlex.quote(self.config)
        for mode in (0o620, 0o602, 0o660, 0o666):
            os.chmod(self.config, mode)
            message = (f"{self.config} is writable by group or others (mode {mode:04o}); refusing to use it "
                       f"(chmod 600 {quoted})")
            with self.subTest(mode=oct(mode)), self.assert_failure(2, message=message):
                cli.load_config(self.config)
        result = self.run_cli("derive", "srv")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"is writable by group or others (mode 0666); refusing to use it", result.stderr)
        self.assertEqual((result.stdout, self.calls()), (b"", []))

    def test_file_that_others_can_read_earns_a_warning(self):
        self.write_host()
        for mode, problem in ((0o600, None), (0o400, None), (0o640, "0640"), (0o604, "0604"), (0o644, "0644")):
            os.chmod(self.config, mode)
            with self.subTest(mode=oct(mode)), captured_stderr() as stderr:
                cli.load_config(self.config)
            expected = (f"kaltstart: warning: {self.config} is accessible by group or others (mode {problem}); "
                        f"run: chmod 600 {shlex.quote(self.config)}\n") if problem else ""
            self.assertEqual(stderr.getvalue(), expected)
        with captured_stderr() as stderr:
            cli.load_config(self.config, warn=False)
        self.assertEqual(stderr.getvalue(), "")
        result = self.run_cli("derive", "srv")
        self.assertEqual((result.returncode, result.stdout), (0, expected_secret()))
        self.assertIn(b"kaltstart: warning: ", result.stderr)

    def test_unreadable_file_is_a_configuration_error(self):
        if os.geteuid() == 0:
            self.skipTest("root can read every file")
        self.write_host()
        os.chmod(self.config, 0o000)
        with self.assert_failure(2, f"cannot read {self.config}: "):
            cli.load_config(self.config)
        os.chmod(self.config, 0o600)
        os.remove(self.config)
        os.mkdir(self.config)
        with self.assert_failure(2, f"cannot read {self.config}: "):
            cli.load_config(self.config)

    def test_config_option_overrides_the_default_path(self):
        self.write_host()
        other = os.path.join(self.tmp, "other.ini")
        with open(other, "w", encoding="utf-8") as handle:
            handle.write(f"[host elsewhere]\nhost = 203.0.113.20\nsalt = {SALT}\n")
        os.chmod(other, 0o600)
        result = self.run_cli("--config", other, "list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith(b"host elsewhere: root@203.0.113.20 "), result.stdout)
        self.assertNotIn(b"srv", result.stdout)

    def test_default_path_without_xdg_config_home(self):
        directory = os.path.join(self.home, ".config", "kaltstart")
        os.makedirs(directory)
        with open(os.path.join(directory, "config.ini"), "w", encoding="utf-8") as handle:
            handle.write(f"[host fallback]\nhost = srv03.example.net\nsalt = {SALT}\n")
        os.chmod(os.path.join(directory, "config.ini"), 0o600)
        self.write_host()  # below XDG_CONFIG_HOME: must not be read
        for variant in ({"unset": ["XDG_CONFIG_HOME"]}, {"env": {"XDG_CONFIG_HOME": ""}}):
            with self.subTest(variant=variant):
                result = self.run_cli("list", **variant)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.startswith(b"host fallback: root@srv03.example.net "), result.stdout)

    def test_list_prints_every_section_with_short_ids_and_salts(self):
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\n"
                          f"[token spare]\ncredential_id = {OTHER_CRED_ID}\nrp_id = example.net\npin = no\n"
                          "device = /dev/hidraw9\n"
                          f"[host srv]\nhost = 127.0.0.1\nport = 2222\nsalt = {SALT}\n"
                          f"[host big]\nhost = srv01.example.net\nuser = unlock\nsalt = {OTHER_SALT}\ntoken = spare\n"
                          "prompts = 2\nbooted_port = 22\nprobe = no\ndevices = /dev/sda3 /dev/sdb3\n")
        result = self.run_cli("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().splitlines(), [
            f"token main: rp_id=kaltstart credential_id={CRED_ID[:8]}... pin=yes device=auto",
            f"token spare: rp_id=example.net credential_id={OTHER_CRED_ID[:8]}... pin=no device=/dev/hidraw9",
            f"host srv: root@127.0.0.1 port=2222 token=(not set) salt={SALT[:8]}... prompts=1 devices=none",
            f"host big: unlock@srv01.example.net port=22 booted_port=22 probe=no token=spare salt={OTHER_SALT[:8]}... "
            "prompts=2 devices=/dev/sda3,/dev/sdb3"])
        self.assertEqual(result.stderr, b"")

    def test_list_validates_every_section(self):
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\n"
                          f"[host srv]\nhost = 127.0.0.1\nsalt = {SALT}\ntoken = spare\n")
        status, out, err = self.run_main("list")
        self.assertEqual((status, err), (2, f"kaltstart: no [token spare] section in {self.config}\n"))
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\npin = perhaps\n")
        status, out, err = self.run_main("list")
        self.assertEqual((status, out, err), (2, "", "kaltstart: [token main] pin: must be yes or no\n"))

    def test_list_warns_once_about_hosts_that_share_a_salt(self):
        self.write_config(f"[host a]\nhost = a.example.net\nsalt = {SALT}\n[host b]\nhost = b.example.net\nsalt = {SALT}\n"
                          f"[host c]\nhost = c.example.net\nsalt = {OTHER_SALT}\n"
                          f"[host d]\nhost = d.example.net\nsalt = {SALT}\n")
        status, out, err = self.run_main("list")
        self.assertEqual(status, 0)
        self.assertEqual(len(out.splitlines()), 4)
        self.assertEqual(err, "kaltstart: warning: [host a] and [host b], [host d] have the same salt; with the same "
                              "token they share one passphrase, which is intended only for sections that describe "
                              "the same server\n")

    def test_list_escapes_what_it_prints(self):
        # Neither a control character nor a line break: check_text lets it pass, the output must not.
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\nrp_id = evil\u202enet\ndevice = /dev/hid\u2028raw\n")
        status, out, _ = self.run_main("list")
        self.assertEqual((status, out), (0, f"token main: rp_id=evil\\u202enet credential_id={CRED_ID[:8]}... pin=yes "
                                            "device=/dev/hid\\u2028raw\n"))

    def test_version_and_usage_errors(self):
        result = self.run_cli("--version")
        self.assertEqual((result.returncode, result.stdout.strip()), (0, cli.__version__.encode()))
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"usage: kaltstart", result.stderr)
        result = self.run_cli("frobnicate")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"invalid choice: 'frobnicate'", result.stderr)

    def test_time_limits_are_checked_before_anything_happens(self):
        self.write_host(port=self.open_port())  # a valid configuration: the option itself must be what is rejected
        for option, value in (("--wait", "-1"), ("--boot-timeout", "nan"), ("--wait", "soon")):
            with self.subTest(option=option, value=value):
                result = self.run_cli("unlock", "srv", option, value)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"kaltstart unlock: error: argument " + option.encode(), result.stderr)
        self.assertIn(b"argument --boot-timeout: must be a number of seconds between 0 and 31536000 (one year)",
                      self.run_cli("unlock", "srv", "--boot-timeout", "inf").stderr)
        self.assertEqual(self.calls(), [])



class DeviceDetectionTests(CliTestCase):
    def detect(self, listing, **env):
        """Search for the device with this output of "fido2-token -L". What is printed is kept in self.printed."""
        with mock.patch.dict(os.environ, dict(env, STUB_TOKEN_LIST=listing)), captured_stderr() as stderr:
            try:
                return cli.detect_device()
            finally:
                self.printed = stderr.getvalue()

    def test_one_device(self):
        self.assertEqual((self.detect(DEVICE_LINE), self.printed), ("/dev/hidraw5", ""))
        self.assertEqual(self.calls("fido2-token")[0]["argv"], ["-L"])
        self.assertEqual(self.detect("\nsome other line\n" + SECOND_DEVICE), "/dev/hidraw7")

    def test_no_device(self):
        with self.assert_failure(3, "no FIDO2 device found; plug in the token or pass --device"):
            self.detect("")

    def test_two_devices_are_listed(self):
        with self.assert_failure(3, "2 FIDO2 devices found; choose one with --device"):
            self.detect(DEVICE_LINE + SECOND_DEVICE)
        self.assertEqual(self.printed, "kaltstart: found: " + DEVICE_LINE + "kaltstart: found: " + SECOND_DEVICE)

    def test_listing_is_escaped(self):
        # The product string comes from the device.
        with self.assert_failure(3):
            self.detect(DEVICE_LINE + "/dev/hidraw7: vendor=0x1234, product=0x9abc (Evil \x1b[2J\u202e Token)\n")
        self.assertIn("kaltstart: found: /dev/hidraw7: vendor=0x1234, product=0x9abc (Evil \\x1b[2J\\u202e Token)\n",
                      self.printed)
        self.assertNotIn("\x1b", self.printed)

    def test_failing_listing(self):
        with self.assert_failure(3, "fido2-token -L failed with exit status 1"):
            self.detect(DEVICE_LINE, STUB_TOKEN_RC="1")

    def test_device_path_cannot_be_an_option_or_hold_control_characters(self):
        token = cli.parse_token("main", {"credential_id": CRED_ID})
        for option in ("-x", "--help", "/dev/hidraw1\n/dev/hidraw2", "/dev/hid\x1braw1"):
            with self.subTest(option=option), self.assert_failure(3, "invalid FIDO2 device path"):
                cli.pick_device(option, token)
        # A device node could bear such a name: the list of fido2-token is not trusted either.
        for listing in ("-x: vendor=0x1234, product=0x5678 (Example)\n",
                        "/dev/hid\x1braw5: vendor=0x1234, product=0x5678 (Example)\n"):
            with self.subTest(listing=listing), mock.patch.dict(os.environ, {"STUB_TOKEN_LIST": listing}), \
                    self.assert_failure(3, "invalid FIDO2 device path"):
                cli.pick_device(None, token)
        self.assertEqual(cli.pick_device("/dev/hidraw2", token), "/dev/hidraw2")

    def test_exit_codes_and_messages(self):
        self.write_host(device=None)
        for env, message in (({"STUB_TOKEN_LIST": ""}, b"kaltstart: no FIDO2 device found"),
                             ({"STUB_TOKEN_LIST": DEVICE_LINE + SECOND_DEVICE}, b"kaltstart: found: /dev/hidraw7: "),
                             ({"STUB_TOKEN_RC": "1"}, b"kaltstart: fido2-token -L failed with exit status 1")):
            with self.subTest(env=env):
                result = self.run_cli("derive", "srv", env=env)
                self.assertEqual((result.returncode, result.stdout), (3, b""))
                self.assertIn(message, result.stderr)
        result = self.run_cli("derive", "srv", "--device=-x")
        self.assertEqual((result.returncode, result.stdout), (3, b""))
        self.assertEqual(result.stderr, b"kaltstart: invalid FIDO2 device path\n")
        self.assertEqual(self.calls("fido2-assert"), [])

    def test_missing_fido2_tools(self):
        self.write_host(device=None)
        self.remove_stub("fido2-token")
        result = self.run_cli("derive", "srv")
        self.assertEqual((result.returncode, result.stdout), (3, b""))
        self.assertEqual(result.stderr, b"kaltstart: fido2-token not found in PATH (install fido2-tools)\n")
        self.remove_stub("fido2-assert")
        result = self.run_cli("derive", "srv")
        self.assertEqual((result.returncode, result.stdout), (3, b""))
        self.assertEqual(result.stderr, b"kaltstart: fido2-assert not found in PATH (install fido2-tools)\n")


class DeriveTests(CliTestCase):
    def test_happy_path(self):
        self.write_host(device=None)
        result = self.run_cli("derive", "srv")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected_secret())
        self.assertEqual(len(result.stdout), 44)  # no newline
        self.assertEqual(result.stderr, b"kaltstart: asking token 'main' on /dev/hidraw5: enter the PIN if asked, "
                                        b"then touch the token\n")
        self.assertEqual([call["tool"] for call in self.calls()], ["fido2-token", "fido2-assert"])
        (call,) = self.calls("fido2-assert")
        self.assertEqual(call["argv"],
                         ["-G", "-h", "-t", "up=true", "-t", "pin=true", "-i", call["param_file"], "/dev/hidraw5"])
        client_data_hash, rp_id, credential_id, salt, rest = call["params"]
        self.assertEqual(len(base64.b64decode(client_data_hash, validate=True)), 32)
        self.assertEqual((rp_id, credential_id, salt, rest), ("kaltstart", CRED_ID, SALT, ""))
        # The parameter file is private, lies below TMPDIR and is gone afterwards.
        self.assertEqual((call["param_mode"], call["dir_mode"]), (0o600, 0o700))
        self.assertEqual(os.path.dirname(os.path.dirname(call["param_file"])), self.tmpdir)
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_passphrase_is_written_to_standard_output_only(self):
        self.write_host(device=None)
        result = self.run_cli("-v", "derive", "srv")
        self.assertEqual((result.returncode, result.stdout), (0, expected_secret()))
        self.assertIn(b"kaltstart: run: ", result.stderr)
        self.assertNotIn(expected_secret(), result.stderr)
        self.assert_no_trace_of(expected_secret())

    def test_each_derivation_uses_a_fresh_client_data_hash(self):
        self.write_host()
        self.assertEqual(self.run_cli("derive", "srv").stdout, self.run_cli("derive", "srv").stdout)
        first, second = self.calls("fido2-assert")
        self.assertNotEqual(first["params"][0], second["params"][0])

    def test_pin_no_and_device_sources(self):
        self.write_host(token_extra="pin = no", device="/dev/hidraw9")
        result = self.run_cli("derive", "srv")
        self.assertEqual((result.returncode, result.stdout), (0, expected_secret(pin=False)))
        self.assertEqual(self.run_cli("derive", "srv", "--device", "/dev/hidraw2").returncode, 0)
        first, second = self.calls("fido2-assert")
        self.assertEqual(first["argv"], ["-G", "-h", "-t", "up=true", "-i", first["param_file"], "/dev/hidraw9"])
        self.assertEqual(second["argv"][-1], "/dev/hidraw2")  # the option wins over the token section
        self.assertEqual(self.calls("fido2-token"), [])  # no search needed
        self.assertNotEqual(expected_secret(pin=False), expected_secret())

    def test_token_option_selects_the_credential(self):
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\ndevice = /dev/hidraw5\n"
                          f"[token spare]\ncredential_id = {OTHER_CRED_ID}\ndevice = /dev/hidraw6\n"
                          f"[host srv]\nhost = 127.0.0.1\nsalt = {SALT}\ntoken = main\n")
        result = self.run_cli("derive", "srv", "--token", "spare")
        self.assertEqual((result.returncode, result.stdout), (0, expected_secret(credential_id=OTHER_CRED_ID)))
        self.assertIn(b"asking token 'spare' on /dev/hidraw6", result.stderr)
        self.assertEqual(self.calls("fido2-assert")[0]["params"][2], OTHER_CRED_ID)
        self.assertEqual(self.run_cli("derive", "srv").stdout, expected_secret())
        result = self.run_cli("derive", "srv", "--token", "absent")
        self.assertEqual((result.returncode, result.stdout), (2, b""))
        self.assertIn(b"kaltstart: no [token absent] section in ", result.stderr)

    def test_relying_party_id_of_the_token_section_is_used(self):
        self.write_host(token_extra="rp_id = example.net")
        result = self.run_cli("derive", "srv")
        self.assertEqual((result.returncode, result.stdout), (0, expected_secret(rp_id="example.net")))
        self.assertEqual(self.calls("fido2-assert")[0]["params"][1], "example.net")
        self.assertNotEqual(expected_secret(rp_id="example.net"), expected_secret())

    def test_trailing_blank_lines_are_ignored(self):
        self.write_host()
        result = self.run_cli("derive", "srv", env={"STUB_ASSERT_MODE": "blank-lines"})
        self.assertEqual((result.returncode, result.stdout), (0, expected_secret()))

    def test_unusable_token_output(self):
        self.write_host()
        config = cli.load_config(self.config)
        host, token = config.host("srv"), config.token("main")
        unusable = "the token returned no usable hmac-secret value"
        for mode, message in (("empty", unusable), ("garbage", unusable), ("short", unusable), ("truncated", unusable),
                              ("fail", "fido2-assert failed with exit status 1")):
            with self.subTest(mode=mode), mock.patch.dict(os.environ, {"STUB_ASSERT_MODE": mode}), \
                    captured_stderr(), self.assert_failure(3, message):
                cli.derive_passphrase(token, host, None)
        result = self.run_cli("derive", "srv", env={"STUB_ASSERT_MODE": "truncated"})
        self.assertEqual((result.returncode, result.stdout), (3, b""))
        self.assertIn(b"kaltstart: " + unusable.encode(), result.stderr)

    def test_refuses_a_terminal(self):
        self.write_host()
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        result = self.run_cli("derive", "srv", stdout=slave)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"kaltstart: refusing to write the passphrase to a terminal "
                                        b"(use --allow-tty to override)\n")
        self.assertEqual(self.calls(), [])
        result = self.run_cli("derive", "srv", "--allow-tty", stdout=slave)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(os.read(master, 1024), expected_secret())

    def test_reader_that_has_gone_is_exit_1(self):
        # Without care the interpreter would notice the lost output only when it exits, with status 120.
        self.write_host()
        for command in (["derive", "srv"], ["list"]):
            reader, writer = os.pipe()
            os.close(reader)
            try:
                result = self.run_cli(*command, stdout=writer)
            finally:
                os.close(writer)
            with self.subTest(command=command):
                self.assertEqual(result.returncode, 1)
                self.assertTrue(result.stderr.endswith(b"kaltstart: the output could not be written (broken pipe)\n"),
                                result.stderr)
                self.assertNotIn(expected_secret(), result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)


class InitTests(CliTestCase):
    def test_second_token_names_the_hosts_that_need_the_token_option(self):
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\n\n[host loose]\nhost = 127.0.0.1\nsalt = {SALT}\n\n"
                          f"[host bound]\nhost = 127.0.0.2\nsalt = {OTHER_SALT}\ntoken = main\n")
        result = self.run_cli("init", "--token", "backup", "--device", "/dev/hidraw5")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.decode().splitlines()[-1], "kaltstart: note: the file now has several token "
                         "sections; [host loose] has no token key and needs --token from now on")
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\n\n[host a]\nhost = 127.0.0.1\nsalt = {SALT}\n\n"
                          f"[host b]\nhost = 127.0.0.2\nsalt = {OTHER_SALT}\n")
        result = self.run_cli("init", "--token", "backup", "--device", "/dev/hidraw5")
        self.assertEqual(result.stderr.decode().splitlines()[-1], "kaltstart: note: the file now has several token "
                         "sections; [host a], [host b] have no token key and need --token from now on")
        # The first token section and a file in which every host names its token give no note.
        self.write_config(f"[host bound]\nhost = 127.0.0.2\nsalt = {OTHER_SALT}\n")
        result = self.run_cli("init", "--device", "/dev/hidraw5")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b"note:", result.stderr)

    def test_takes_line_five_and_appends(self):
        old = f"# notes\n[host srv]\nhost = 127.0.0.1\nsalt = {SALT}"  # no trailing newline
        self.write_config(old)
        result = self.run_cli("init", "--rp-id", "example.net", "--no-pin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"kaltstart: added [token main] to {self.config}\n".encode(), result.stderr)
        with open(self.config, encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(text, old + f"\n\n[token main]\nrp_id = example.net\ncredential_id = {STUB_CRED_ID}\npin = no\n")
        token = cli.load_config(self.config).token("main")
        self.assertEqual((token.credential_id, token.rp_id, token.pin), (STUB_CRED_ID, "example.net", False))
        self.assertEqual([call["tool"] for call in self.calls()], ["fido2-token", "fido2-cred"])
        (call,) = self.calls("fido2-cred")
        self.assertEqual(call["argv"], ["-M", "-h", "-i", call["param_file"], "/dev/hidraw5"])
        client_data_hash, rp_id, user_name, user_id, rest = call["params"]
        self.assertEqual(len(base64.b64decode(client_data_hash, validate=True)), 32)
        self.assertEqual(len(base64.b64decode(user_id, validate=True)), 16)
        self.assertEqual((rp_id, user_name, rest), ("example.net", "kaltstart", ""))
        self.assertEqual((call["param_mode"], call["dir_mode"], os.listdir(self.tmpdir)), (0o600, 0o700, []))

    def test_creates_private_file_and_directory(self):
        result = self.run_cli("init", "--token", "backup", "--device", "/dev/hidraw3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(self.config).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.config)).st_mode), 0o700)
        token = cli.load_config(self.config).token("backup")
        self.assertEqual((token.credential_id, token.rp_id, token.pin), (STUB_CRED_ID, "kaltstart", True))
        (call,) = self.calls()
        # Protection level 3: the token itself requires user verification for this credential.
        self.assertEqual(call["argv"], ["-M", "-h", "-c", "3", "-i", call["param_file"], "/dev/hidraw3"])

    def test_refuses_existing_section(self):
        self.write_host()
        with open(self.config, encoding="utf-8") as handle:
            before = handle.read()
        result = self.run_cli("init")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, f"kaltstart: [token main] already exists in {self.config}\n".encode())
        self.assertEqual(self.calls(), [])
        with open(self.config, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before)

    def test_token_failures_write_nothing(self):
        no_id = b"kaltstart: fido2-cred did not print a credential ID on line 5\n"
        for env, message in (({"STUB_CRED_RC": "1"}, b"kaltstart: fido2-cred failed with exit status 1\n"),
                             ({"STUB_CRED_MODE": "short"}, no_id), ({"STUB_CRED_ID": "not base64!"}, no_id),
                             ({"STUB_CRED_ID": NON_CANONICAL}, no_id),
                             ({"STUB_TOKEN_LIST": ""}, b"kaltstart: no FIDO2 device found; plug in the token or pass "
                                                       b"--device\n")):
            with self.subTest(env=env):
                result = self.run_cli("init", env=env)
                self.assertEqual(result.returncode, 3)
                self.assertTrue(result.stderr.endswith(message), result.stderr)
                self.assertFalse(os.path.exists(self.config))

    def test_names_and_relying_party_ids_are_validated(self):
        name = "--token: invalid name (allowed: letters, digits, '.', '_', '-'; at most 64 characters)"
        text = "--rp-id: must be a non-empty single-line value without surrounding white space"
        for arguments, message in ((["--token", "a]\nx = y\n[token b"], name), (["--token", "two words"], name),
                                   (["--token", "x" * 65], name), (["--token=-x"], name),
                                   (["--rp-id", " kaltstart"], text), (["--rp-id", "kaltstart "], text),
                                   (["--rp-id", ""], text), (["--rp-id=-x"], text), (["--rp-id", "a\nb"], text),
                                   (["--rp-id", "a\x9bb"], text)):
            with self.subTest(arguments=arguments):
                status, _, err = self.run_main("init", *arguments)
                self.assertEqual(status, 2)
                self.assertTrue(err.startswith("kaltstart: " + message), err)
        self.assertEqual(self.calls(), [])  # the token was never asked
        self.assertFalse(os.path.exists(self.config))

    def test_unwritable_configuration_fails_before_the_token_is_used(self):
        if os.geteuid() == 0:
            self.skipTest("root can write everywhere")
        directory = os.path.dirname(self.config)

        def refused(probe):
            status, _, err = self.run_main("init")
            self.assertEqual((status, err), (2, f"kaltstart: cannot write {self.config}: no write permission for {probe}\n"))

        os.chmod(self.xdg, 0o500)
        refused(self.xdg)  # neither the file nor its directory exists
        os.chmod(self.xdg, 0o700)
        self.write_config(f"[host srv]\nhost = 127.0.0.1\nsalt = {SALT}\n", mode=0o400)
        refused(self.config)
        os.remove(self.config)
        os.chmod(directory, 0o500)
        refused(directory)
        self.assertEqual(self.calls(), [])  # PIN and touch were not spent

    def test_new_token_and_host_work_together(self):
        self.assertEqual(self.run_cli("init").returncode, 0)
        self.assertEqual(self.run_cli("add-host", "srv", "--host", "srv01.example.net").returncode, 0)
        config = cli.load_config(self.config)
        host = config.host("srv")
        self.assertEqual((host.token, config.token_for(host, None).credential_id), ("main", STUB_CRED_ID))
        result = self.run_cli("derive", "srv")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected_secret(credential_id=STUB_CRED_ID, salt=host.salt))
        self.assertIn("pin=true", self.calls("fido2-assert")[0]["argv"])


class AddHostTests(CliTestCase):
    def section(self, name):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(self.config, encoding="utf-8")
        return dict(parser[f"host {name}"])

    def test_writes_a_fresh_salt(self):
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\n")
        # HOME is a fixed path here: the identity path must not depend on where the test directory lies.
        result = self.run_cli("add-host", "srv", "--host", "srv01.example.net", "--port", "2222", "--user", "unlock",
                              "--identity", "~/.ssh/id_unlock", "--known-hosts", "~/.ssh/kh_unlock",
                              "--booted-port", "22", "--token", "main",
                              "--device-on-server", "/dev/sda3", "--device-on-server", "/dev/sdb3",
                              env={"HOME": "/nonexistent/home"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, f"kaltstart: added [host srv] to {self.config}\n".encode())
        self.assertEqual(self.run_cli("add-host", "other", "--host", "203.0.113.2").returncode, 0)
        srv, other = self.section("srv"), self.section("other")
        for salt in (srv.pop("salt"), other.pop("salt")):
            self.assertEqual(len(base64.b64decode(salt, validate=True)), 32)
        self.assertNotEqual(self.section("srv")["salt"], self.section("other")["salt"])
        self.assertEqual(srv, {"host": "srv01.example.net", "port": "2222", "user": "unlock",
                               "identity": "~/.ssh/id_unlock", "known_hosts": "~/.ssh/kh_unlock", "booted_port": "22",
                               "token": "main", "devices": "/dev/sda3 /dev/sdb3"})
        self.assertEqual(other, {"host": "203.0.113.2", "port": "22", "user": "root", "token": "main"})
        with mock.patch.dict(os.environ, {"HOME": "/nonexistent/home"}):
            host = cli.load_config(self.config).host("srv")
        self.assertEqual((host.identity, host.known_hosts),
                         ("/nonexistent/home/.ssh/id_unlock", "/nonexistent/home/.ssh/kh_unlock"))
        self.assertEqual(host.devices, ["/dev/sda3", "/dev/sdb3"])
        self.assertEqual(stat.S_IMODE(os.stat(self.config).st_mode), 0o600)

    def test_named_token_section_must_exist(self):
        result = self.run_cli("add-host", "srv", "--host", "srv01.example.net", "--token", "main")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, f"kaltstart: no [token main] section in {self.config} "
                                        "(the file does not exist)\n".encode())
        self.assertFalse(os.path.exists(self.config))
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\n")
        result = self.run_cli("add-host", "srv", "--host", "srv01.example.net", "--token", "spare")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, f"kaltstart: no [token spare] section in {self.config}\n".encode())
        with open(self.config, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), f"[token main]\ncredential_id = {CRED_ID}\n")  # nothing was written

    def test_name_may_follow_the_options(self):
        # The usage line prints NAME last; an option that takes several values would swallow it.
        result = self.run_cli("add-host", "--host", "srv01.example.net", "--device-on-server", "/dev/sda3", "srv")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(cli.load_config(self.config).host("srv").devices, ["/dev/sda3"])

    def test_refuses_duplicates(self):
        self.assertEqual(self.run_cli("add-host", "srv", "--host", "a.example.net").returncode, 0)
        with open(self.config, encoding="utf-8") as handle:
            before = handle.read()
        result = self.run_cli("add-host", "srv", "--host", "b.example.net")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, f"kaltstart: [host srv] already exists in {self.config}\n".encode())
        with open(self.config, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before)

    def test_only_token_section_is_recorded(self):
        # A host that names its token stays unambiguous when a second token is added.
        self.assertEqual(self.run_main("add-host", "none", "--host", "a.example.net")[0], 0)
        self.assertNotIn("token", self.section("none"))
        with open(self.config, "a", encoding="utf-8") as handle:
            handle.write(f"\n[token main]\ncredential_id = {CRED_ID}\n")
        self.assertEqual(self.run_main("add-host", "one", "--host", "b.example.net")[0], 0)
        self.assertEqual(self.section("one")["token"], "main")
        with open(self.config, "a", encoding="utf-8") as handle:
            handle.write(f"\n[token spare]\ncredential_id = {OTHER_CRED_ID}\n")
        self.assertEqual(self.run_main("add-host", "two", "--host", "c.example.net")[0], 0)
        self.assertNotIn("token", self.section("two"))
        self.assertEqual(self.run_main("add-host", "chosen", "--host", "d.example.net", "--token", "spare")[0], 0)
        self.assertEqual(self.section("chosen")["token"], "spare")

    def test_rejects_hostile_values(self):
        control, name = "must not contain control characters", "invalid host name or address"
        port = "must be an integer between 1 and 65535"
        host = ["--host", "srv01.example.net"]
        cases = ((["--host=-oProxyCommand=evil"], "host: " + name), (["--host", "srv01 example.net"], "host: " + name),
                 (["--host", "srv01.example.net;id"], "host: " + name), (["--host", "$(id)"], "host: " + name),
                 (["--host", "srv01.example.net\nport = 1"], "host: " + control),
                 (host + ["--user=-lroot"], "user: invalid user name"), (host + ["--user", "a;b"], "user: invalid user name"),
                 (host + ["--port", "0"], "port: " + port), (host + ["--port", "99999"], "port: " + port),
                 (host + ["--booted-port", "65536"], "booted_port: " + port),
                 (host + ["--token", "x\n[host evil]"], "token: " + control),
                 (host + ["--token", "two words"], "token: invalid name"),
                 (host + ["--identity", "/a\nuser = x"], "identity: " + control),
                 (host + ["--identity", "keys/id"], "identity: must be an absolute path, or start with '~'"),
                 (host + ["--known-hosts", "/keys/known hosts"], "known_hosts: path must not contain white space"),
                 (host + ["--device-on-server", "sda3"], "devices: must be an absolute path on the server"),
                 # Split at the line break, both parts would pass as devices: only the check for control
                 # characters keeps the second one from becoming a line of its own in the file.
                 (host + ["--device-on-server", "/dev/sda3\n/host=evil"], "devices: " + control),
                 (host + ["--device-on-server", "/dev/sda3", "--device-on-server", "/dev/sdb3\x1b"], "devices: " + control))
        for arguments, message in cases:
            with self.subTest(arguments=arguments):
                status, _, err = self.run_main("add-host", "srv", *arguments)
                self.assertEqual(status, 2)
                self.assertTrue(err.startswith("kaltstart: [host srv] " + message), err)
                self.assertFalse(os.path.exists(self.config))
        status, _, err = self.run_main("add-host", "bad name", "--host", "srv01.example.net")
        self.assertEqual(status, 2)
        self.assertTrue(err.startswith("kaltstart: NAME: invalid name"), err)
        self.assertFalse(os.path.exists(self.config))


class CheckTests(CliTestCase):
    def prepare(self, port=2222, extra=""):
        self.plain_directory_needed()
        self.identity = os.path.join(self.home, "id_unlock")
        self.known_hosts = os.path.join(self.home, "kh_unlock")
        for path in (self.identity, self.known_hosts):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("x\n")
        self.write_host(port=port, extra=f"identity = {self.identity}\nknown_hosts = {self.known_hosts}\n{extra}")

    def check(self, *names, env=None):
        """Run the command in the test process. Returns the exit status and the lines it printed."""
        status, out, err = self.run_main("check", *(names or ("srv",)), env=env)
        self.assertEqual(out, "")
        return status, err.splitlines()

    def test_all_checks_pass(self):
        self.prepare()
        result = self.run_cli("check", "srv")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr.decode().splitlines(), ["kaltstart: ok:   " + line for line in (
            f"configuration file {self.config}", "executable fido2-assert", "executable fido2-token", "executable ssh",
            "executable ssh-keygen", "[host srv] is valid", "[token main] is valid", f"identity file {self.identity}",
            f"known_hosts file {self.known_hosts}", "known_hosts entry for [127.0.0.1]:2222")])
        # The token is not used and no server is contacted.
        (call,) = self.calls()
        self.assertEqual((call["tool"], call["argv"]), ("ssh-keygen", ["-F", "[127.0.0.1]:2222", "-f", self.known_hosts]))

    def test_port_22_uses_the_plain_host_name(self):
        self.write_host(port=22)
        status, lines = self.check()
        self.assertEqual((status, lines[-1]), (0, "kaltstart: ok:   known_hosts entry for 127.0.0.1"))
        self.assertEqual(self.calls()[0]["argv"], ["-F", "127.0.0.1"])  # the known_hosts file of the user is searched

    def test_failures(self):
        self.prepare()
        status, lines = self.check(env={"STUB_KEYGEN_RC": "1"})
        self.assertEqual(status, 2)
        self.assertEqual([line for line in lines if "FAIL" in line],
                         ["kaltstart: FAIL: known_hosts entry for [127.0.0.1]:2222"])
        os.remove(self.identity)
        os.remove(self.known_hosts)
        self.remove_stub("fido2-token")
        self.remove_stub("ssh-keygen")
        os.chmod(self.config, 0o644)
        status, lines = self.check()
        self.assertEqual(status, 2)
        self.assertEqual([line for line in lines if "FAIL" in line], ["kaltstart: FAIL: " + line for line in (
            f"configuration file {self.config} is accessible by group or others (mode 0644)", "executable fido2-token",
            "executable ssh-keygen", f"identity file {self.identity}", f"known_hosts file {self.known_hosts}")])
        self.assertFalse([line for line in lines if "known_hosts entry" in line])  # nothing to search with

    def test_unusable_sections(self):
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\n[token spare]\ncredential_id = {CRED_ID}\n"
                          f"[host srv]\nhost = 127.0.0.1\nsalt = {SALT}\n[host bad]\nhost = 127.0.0.1\n")
        status, lines = self.check()
        self.assertEqual(status, 2)
        self.assertIn(f"kaltstart: FAIL: [host srv] names no token and {self.config} has 2 token sections; "
                      "set the token key of the host or use --token", lines)
        self.assertEqual(self.check("bad"), (2, lines[:5] + ["kaltstart: FAIL: [host bad] salt: required key is missing"]))
        self.assertEqual(self.check("absent")[1][5], f"kaltstart: FAIL: no [host absent] section in {self.config}")

    def test_file_or_directory_that_others_can_write(self):
        self.write_host()
        os.chmod(os.path.dirname(self.config), 0o770)
        status, lines = self.check()
        self.assertEqual(status, 2)
        self.assertEqual(lines[:2], [f"kaltstart: ok:   configuration file {self.config}",
                                     f"kaltstart: FAIL: directory {os.path.dirname(self.config)} is writable by group "
                                     "or others"])
        os.chmod(os.path.dirname(self.config), 0o750)  # readable only: the file in it cannot be replaced
        self.assertEqual(self.check()[0], 0)
        os.chmod(self.config, 0o660)
        status, lines = self.check()
        self.assertEqual(status, 2)
        self.assertEqual(lines[0], f"kaltstart: FAIL: configuration file {self.config} is writable by group or others "
                                   "(mode 0660)")
        self.assertIn("refusing to use it", lines[5])  # and nothing is read from it

    def test_missing_configuration_file(self):
        status, lines = self.check()
        self.assertEqual(status, 2)
        self.assertEqual(lines[0], f"kaltstart: FAIL: configuration file {self.config}: No such file or directory")
        self.assertEqual(lines[5:], [f"kaltstart: FAIL: no [host srv] section in {self.config} (the file does not exist)"])

    def test_note_for_a_shared_salt(self):
        self.write_host(extra=f"[host twin]\nhost = 203.0.113.9\nsalt = {SALT}\n"
                              f"[host third]\nhost = 203.0.113.10\nsalt = {SALT}\n"
                              f"[host apart]\nhost = 203.0.113.11\nsalt = {OTHER_SALT}")
        status, lines = self.check()
        self.assertEqual(status, 0, lines)  # a note, not a failure
        self.assertEqual(lines[-1], "kaltstart: note: [host srv] has the same salt as [host twin], [host third]; with the "
                                    "same token they share one passphrase, which is intended only for sections that "
                                    "describe the same server")
        status, lines = self.check("apart")
        self.assertEqual(status, 0, lines)
        self.assertFalse([line for line in lines if "note" in line])


class PortWaitTests(CliTestCase):
    def waited(self, seconds):
        """wait_for_port against a port that never opens, with a clock that only the program's sleeping moves."""
        now, sleeps = [1000.0], []

        def sleep(duration):
            self.assertLess(len(sleeps), 1000, "wait_for_port does not give up")
            sleeps.append(duration)
            now[0] += duration

        with mock.patch.object(cli.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(cli.time, "sleep", side_effect=sleep), \
                mock.patch.object(cli, "port_open", return_value=False) as probe:
            self.assertFalse(cli.wait_for_port("srv01.example.net", 22, seconds))
        return probe.call_count, sleeps

    def test_open_and_closed_port(self):
        self.assertTrue(cli.port_open("127.0.0.1", self.open_port()))
        self.assertFalse(cli.port_open("127.0.0.1", self.closed_port()))
        with mock.patch.object(cli.time, "sleep", side_effect=AssertionError("a single attempt does not wait")):
            self.assertTrue(cli.wait_for_port("127.0.0.1", self.open_port(), 0))
            self.assertFalse(cli.wait_for_port("127.0.0.1", self.closed_port(), 0))

    def test_port_that_opens_later(self):
        sock = self.reserved_socket()
        with mock.patch.object(cli.time, "sleep", side_effect=lambda seconds: sock.listen(1)) as sleep:
            self.assertTrue(cli.wait_for_port("127.0.0.1", sock.getsockname()[1], 10))
        sleep.assert_called_once_with(cli.RETRY_INTERVAL)  # refused once, then accepted

    def test_gives_up_at_the_deadline_and_not_before(self):
        self.assertEqual(self.waited(5), (4, [2.0, 2.0, 1.0]))  # attempts after 0, 2, 4 and 5 seconds
        self.assertEqual(self.waited(600)[0], 301)

    def test_zero_seconds_is_a_single_attempt(self):
        self.assertEqual(self.waited(0), (1, []))


class TopLevelTests(CliTestCase):
    def failing_list(self, error, *options):
        """Run "list" in the test process with a command function that raises ERROR."""
        with mock.patch.object(cli, "cmd_list", side_effect=error):
            status, _, err = self.run_main(*options, "list")
        return status, err

    def test_unexpected_error_is_one_line(self):
        self.assertEqual(self.failing_list(RuntimeError("boom")), (1, "kaltstart: internal error: RuntimeError: boom\n"))
        self.assertEqual(self.failing_list(RuntimeError("two\nlines \x1b[2J")),
                         (1, "kaltstart: internal error: RuntimeError: two\\x0alines \\x1b[2J\n"))

    def test_traceback_only_with_verbose(self):
        status, err = self.failing_list(RuntimeError("boom"), "-v")
        self.assertEqual(status, 1)
        self.assertIn("Traceback", err)

    def test_keyboard_interrupt(self):
        self.assertEqual(self.failing_list(KeyboardInterrupt()), (130, "kaltstart: interrupted\n"))

    def test_expected_failure_is_its_message_and_its_code(self):
        self.assertEqual(self.failing_list(cli.Failure(5, "refused")), (5, "kaltstart: refused\n"))

    def test_sigterm_sighup_and_sigquit_are_handled_like_an_interrupt_unless_ignored(self):
        for signum in cli.TERMINATION_SIGNALS:
            self.addCleanup(signal.signal, signum, signal.getsignal(signum))
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGQUIT, signal.SIG_DFL)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)  # as under nohup
        during = {}

        def look(args):
            during.update((signum, signal.getsignal(signum)) for signum in cli.TERMINATION_SIGNALS)
            return 0

        with mock.patch.object(cli, "cmd_list", side_effect=look):
            self.assertEqual(self.run_main("list")[0], 0)
        self.assertIs(during[signal.SIGTERM], signal.default_int_handler)
        self.assertIs(during[signal.SIGQUIT], signal.default_int_handler)
        self.assertIs(during[signal.SIGHUP], signal.SIG_IGN)
        # run_main has taken the handlers back.
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        # No core file: it would hold the passphrase.
        self.setrlimit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))

    def test_child_processes_cannot_write_core_files(self):
        if resource.getrlimit(resource.RLIMIT_CORE)[1] == 0:
            self.skipTest("core files are switched off for the test process already")
        self.write_host(port=self.open_port(), device=None)
        result = self.run_cli("unlock", "srv", "--wait", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(call["tool"], call["core"]) for call in self.calls()],
                         [("fido2-token", [0, 0]), ("fido2-assert", [0, 0]), ("ssh", [0, 0])])

    def test_messages_survive_a_closed_standard_error(self):
        class Gone:
            def write(self, text):
                raise BrokenPipeError(errno.EPIPE, "Broken pipe")

            def flush(self):
                raise BrokenPipeError(errno.EPIPE, "Broken pipe")

        with contextlib.redirect_stderr(Gone()):
            cli.say("a message that nobody reads")  # must not raise: the cleanup that follows has to run

    def test_program_file_runs_through_its_interpreter_line(self):
        with open(CLI, "rb") as handle:
            self.assertEqual(handle.readline(), b"#!/usr/bin/env python3\n")
        self.assertTrue(os.access(CLI, os.X_OK))
        interpreter = shutil.which("python3", path=CALLER_PATH)
        if not interpreter or not os.path.exists("/usr/bin/env"):
            self.skipTest("no python3 in the PATH of the caller, or no /usr/bin/env")
        proc = self.start([CLI, "--version"], env={"PATH": os.path.dirname(interpreter)})
        out, err = proc.communicate(timeout=60)
        self.assertEqual((proc.returncode, out.strip(), err), (0, cli.__version__.encode(), b""))
