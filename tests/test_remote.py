# SPDX-License-Identifier: GPL-2.0-only
"""Tests for the ssh transport and for unlock, the command that talks to the initramfs through (stubbed) ssh."""

import contextlib
import io
import os
import signal
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock

from support import (CRED_ID, DEFAULTS, FORCED, INITRAMFS, OTHER_CRED_ID, SALT, SIGNAL_NAMES, CliTestCase,
                     IsolatedTestCase, cli, expected_secret)

SECRET = expected_secret()
PROMPT = "Please unlock disk root_crypt\n"
GAVE_UP = "Error: Timeout reached while waiting for PID 123.\n"
ASKING = "kaltstart: asking token 'main' on /dev/hidraw5: enter the PIN if asked, then touch the token"
CANNOT_TELL = ("kaltstart: cannot tell whether the server was unlocked (the start cannot be confirmed: no booted_port, "
               "probe = no, or the same port on the same machine)")


class SshRunTests(IsolatedTestCase):
    """ssh_run with small Python programs in the place of ssh."""

    def setUp(self):
        super().setUp()
        self.children = []
        self.wait_for_exit = False
        popen = subprocess.Popen

        def start(*args, **options):
            child = popen(*args, start_new_session=True, **options)
            self.children.append(child)
            if self.wait_for_exit:
                child.wait()
            return child

        patcher = mock.patch.object(cli.subprocess, "Popen", side_effect=start)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.end_children)

    def end_children(self):
        """End what the programs left behind: each one was started in a session of its own."""
        for child in self.children:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            for stream in (child.stdin, child.stdout):
                if stream:
                    stream.close()

    def ssh_run(self, script, secret=None, echo=True, **constants):
        """Run SCRIPT in the place of ssh, with constants of the program replaced as given.

        Returns the reply, the lines that were printed and the seconds it took.
        """
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in constants.items():
                stack.enter_context(mock.patch.object(cli, name, value))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            started = time.monotonic()
            reply = cli.ssh_run([sys.executable, "-I", "-c", script], secret, echo)
            elapsed = time.monotonic() - started
        printed = stderr.getvalue()
        self.assertEqual(printed[-1:], "\n" if printed else "")
        return reply, printed.split("\n")[:-1], elapsed

    def test_output_is_relayed_escaped_and_without_the_passphrase(self):
        script = ("import sys\n"
                  "secret = sys.stdin.buffer.read()\n"
                  "sys.stderr.buffer.write(b'first\\r\\nevil \\x1b[2J\\x07\\rback\\n\\xff\\xfe bytes\\n')\n"
                  "sys.stderr.buffer.write(b'seen ' + secret + b' twice ' + secret + b'\\nno newline')\n"
                  "sys.stdout.buffer.write(b'out ' + secret + b'\\nevil \\x1b[2J out\\n')\n"
                  "sys.exit(3)\n")
        reply, printed, _ = self.ssh_run(script, SECRET)
        self.assertEqual(reply.status, 3)
        # Standard error line by line while ssh runs, standard output afterwards.
        self.assertEqual(printed, ["kaltstart: ssh: first",
                                   "kaltstart: ssh: evil \\x1b[2J\\x07\\x0dback",
                                   "kaltstart: ssh: \ufffd\ufffd bytes",
                                   "kaltstart: ssh: seen [passphrase removed] twice [passphrase removed]",
                                   "kaltstart: ssh: no newline",
                                   "kaltstart: remote: out [passphrase removed]",
                                   "kaltstart: remote: evil \\x1b[2J out"])
        # What is returned for evaluation is unescaped, but free of the passphrase as well.
        self.assertEqual(reply.output, b"out [passphrase removed]\nevil \x1b[2J out\n")
        self.assertEqual(reply.errors, b"first\r\nevil \x1b[2J\x07\rback\n\xff\xfe bytes\n"
                                       b"seen [passphrase removed] twice [passphrase removed]\nno newline")

    def test_standard_output_can_be_kept_from_the_terminal(self):
        reply, printed, _ = self.ssh_run("print('for the program only')", echo=False)
        self.assertEqual((reply.status, reply.output, reply.errors, printed), (0, b"for the program only\n", b"", []))

    def test_passphrase_is_the_entire_standard_input(self):
        script = "import sys; print(sys.stdin.buffer.read().hex())"
        self.assertEqual(self.ssh_run(script, SECRET, echo=False)[0].output, SECRET.hex().encode() + b"\n")
        self.assertEqual(self.ssh_run(script, echo=False)[0].output, b"\n")  # without one the input is empty

    def test_ssh_that_ends_before_it_reads_the_passphrase(self):
        # A refused connection: the write into the closed pipe must not hide the exit status.
        self.wait_for_exit = True
        reply, printed, _ = self.ssh_run("import sys; sys.exit('ssh: connect to host: Connection refused')", SECRET)
        self.assertEqual((reply.status, reply.output), (1, b""))
        self.assertEqual(printed, ["kaltstart: ssh: ssh: connect to host: Connection refused"])

    def test_long_error_lines_are_printed_in_pieces(self):
        script = "import sys; sys.stderr.write('0123456789' * 4 + '\\nshort\\n')"
        reply, printed, _ = self.ssh_run(script, LINE_LIMIT=16)
        self.assertEqual(printed, ["kaltstart: ssh: " + piece
                                   for piece in ("0123456789012345", "6789012345678901", "23456789", "short")])
        self.assertEqual(reply.errors, b"0123456789" * 4 + b"\nshort\n")

    def test_passphrase_is_removed_where_it_spans_two_pieces(self):
        # A long line is read in pieces; the passphrase must be found across their boundary.
        for name, limit, before in (("default limit", None, 4080), ("piece shorter than the passphrase", 16, 10)):
            with self.subTest(name):
                script = f"import sys; sys.stderr.write('x' * {before} + {SECRET.decode()!r} + '\\n' + {SECRET.decode()!r})"
                constants = {"LINE_LIMIT": limit} if limit else {}
                reply, printed, _ = self.ssh_run(script, SECRET, **constants)
                self.assertTrue(printed)
                self.assertTrue(all(line.startswith("kaltstart: ssh: ") for line in printed), printed)
                text = "".join(line[len("kaltstart: ssh: "):] for line in printed)
                self.assertEqual(text, "x" * before + "[passphrase removed]" * 2)
                self.assertNotIn(SECRET, reply.errors)
                self.assertEqual(reply.errors.count(b"[passphrase removed]"), 2)

    def test_run_without_a_result_is_ended(self):
        for name, script in (("silent", "import time; time.sleep(60)"),
                             ("output closed", "import os, time; os.close(1); time.sleep(60)")):
            with self.subTest(name):
                reply, printed, elapsed = self.ssh_run(script, SECRET, SESSION_LIMIT=0.3)
                self.assertEqual(reply.status, -signal.SIGKILL)
                self.assertEqual(reply.ended, "no result within 0.3 s")
                self.assertEqual(printed, ["kaltstart: ssh was ended: no result within 0.3 s"])
                self.assertGreaterEqual(elapsed, 0.3)
                self.assertLess(elapsed, 30)

    def test_run_that_sends_too_much_output_is_ended(self):
        script = "import sys, time; sys.stdout.write('x' * {}); sys.stdout.flush(); time.sleep({})"
        reply, printed, elapsed = self.ssh_run(script.format(100000, 60), OUTPUT_LIMIT=1000)
        self.assertEqual(reply.status, -signal.SIGKILL)
        self.assertEqual(printed[0], "kaltstart: ssh was ended: the remote side sent more output than this program accepts")
        self.assertEqual(reply.ended, "the remote side sent more output than this program accepts")
        self.assertLessEqual(len(reply.output), 1000)
        self.assertLess(elapsed, 30)
        # Up to the limit the output is taken.
        reply, printed, _ = self.ssh_run(script.format(1000, 0), echo=False, OUTPUT_LIMIT=1000)
        self.assertEqual((reply.status, reply.output, printed), (0, b"x" * 1000, []))

    def test_error_output_is_printed_in_full_but_kept_up_to_the_limit(self):
        script = "import sys; sys.stderr.write(('e' * 49 + '\\n') * 100)"
        reply, printed, _ = self.ssh_run(script, OUTPUT_LIMIT=1000)
        self.assertEqual(printed, ["kaltstart: ssh: " + "e" * 49] * 100)
        self.assertEqual(reply.errors, (b"e" * 49 + b"\n") * 20)

    def test_process_that_keeps_the_error_stream_open_does_not_block(self):
        # For example a connection-sharing master that ssh leaves behind.
        script = ("import subprocess, sys\n"
                  "subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(30)'],\n"
                  "                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)\n"
                  "print('done')\n")
        reply, printed, elapsed = self.ssh_run(script, RELAY_GRACE=0.2)
        self.assertEqual((reply.status, reply.output, printed), (0, b"done\n", ["kaltstart: remote: done"]))
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertLess(elapsed, 15)

    def test_interruption_ends_ssh(self):
        # Ctrl-C or a termination signal while ssh runs: it must not go on and deliver the passphrase.
        for number, interruption in enumerate((KeyboardInterrupt, SystemExit), start=1):
            with self.subTest(interruption=interruption.__name__):
                with mock.patch.object(cli.select, "select", side_effect=interruption), \
                        self.assertRaises(interruption):
                    self.ssh_run("import time; time.sleep(60)", SECRET)
                self.assertEqual(len(self.children), number)
                self.assertEqual(self.children[-1].returncode, -signal.SIGKILL)  # ended, and waited for


def unlock_argv(port, *configured, destination="root@127.0.0.1", command="cryptroot-unlock"):
    """The arguments of ssh for the initramfs, with what the configuration adds in the middle."""
    return ["-T", "-p", str(port)] + FORCED + INITRAMFS + list(configured) + DEFAULTS + ["--", destination, command]


class UnlockTests(CliTestCase):
    def unlock(self, *args, env=None):
        return self.run_cli("unlock", "srv", "--wait", "0", "--boot-timeout", "0", *args, env=env)

    def lines(self, result):
        return result.stderr.decode().splitlines()

    def test_sends_exactly_the_passphrase(self):
        port = self.open_port()
        self.write_host(port=port, device=None)
        result = self.unlock()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual([call["tool"] for call in self.calls()], ["fido2-token", "fido2-assert", "ssh"])
        self.assertEqual(self.ssh_stdin(0), SECRET)
        self.assertEqual(len(self.ssh_stdin(0)), 44)  # no newline
        self.assertEqual(self.lines(result), [
            f"kaltstart: waiting for 127.0.0.1 port {port}",
            ASKING,
            "kaltstart: sending the passphrase to 127.0.0.1",
            "kaltstart: ssh: cryptsetup: root_crypt set up successfully",
            "kaltstart: remote: Please unlock disk root_crypt",
            "kaltstart: passphrase accepted"])

    def test_secret_never_leaves_the_stdin_pipe(self):
        self.write_host(port=self.open_port(), extra="prompts = 2", device=None)
        result = self.run_cli("-v", "unlock", "srv", "--wait", "0",
                              env={"STUB_SSH_ECHO_STDIN": "1", "STUB_SSH_ECHO_STDIN_ERR": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.count(b"kaltstart: run: "), 4)  # fido2-token, fido2-assert, ssh twice
        self.assertEqual([call["stdin"] for call in self.calls("ssh")], [SECRET, SECRET])
        # A remote side that repeats its input does not get it printed, on either stream.
        self.assertEqual(result.stderr.count(b"kaltstart: ssh: [passphrase removed]"), 2)
        self.assertEqual(result.stderr.count(b"kaltstart: remote: [passphrase removed]"), 2)
        self.assertNotIn(SECRET, result.stderr + result.stdout)
        self.assert_no_trace_of(SECRET)

    def test_ssh_command_line(self):
        port = self.open_port()
        self.write_host(port=port, extra="user = unlock\nidentity = /keys/id_unlock\nknown_hosts = /keys/kh\n"
                                         "ssh_options = -o ConnectTimeout=7 -4")
        self.assertEqual(self.unlock().returncode, 0)
        argv = self.calls("ssh")[0]["argv"]
        # The dedicated known_hosts file is the only source of host keys, the identity the only key that is offered.
        self.assertEqual(argv, unlock_argv(
            port, "-o", "UserKnownHostsFile=/keys/kh", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes", "-i", "/keys/id_unlock", "-o", "ConnectTimeout=7", "-4",
            destination="unlock@127.0.0.1"))
        # ssh uses the first value it obtains: the forced options win, the configured ones beat the defaults.
        configured = argv.index("ConnectTimeout=7")
        for forced in FORCED[1::2] + INITRAMFS[1::2]:
            self.assertLess(argv.index(forced), configured, forced)
        self.assertLess(configured, argv.index("ConnectTimeout=15"))
        destination = argv.index("unlock@127.0.0.1")
        self.assertEqual(destination, len(argv) - 2)  # every option precedes the destination
        self.assertEqual(argv[destination - 1], "--")  # and the options are terminated before it
        self.assertNotIn("BatchMode=yes", argv)

    def test_ssh_command_line_follows_the_configuration(self):
        port = self.open_port()
        for extra, configured in (("", []),
                                  ("known_hosts = /keys/kh", ["-o", "UserKnownHostsFile=/keys/kh",
                                                              "-o", "GlobalKnownHostsFile=/dev/null"]),
                                  ("identity = /keys/id_unlock", ["-o", "IdentitiesOnly=yes", "-i", "/keys/id_unlock"]),
                                  ("ssh_options = -J jump.example.net", ["-J", "jump.example.net"])):
            with self.subTest(extra=extra):
                self.write_host(port=port, extra=extra)
                self.assertEqual(self.unlock().returncode, 0)
                self.assertEqual(self.calls("ssh")[-1]["argv"], unlock_argv(port, *configured))

    def test_remote_command_is_the_configured_one(self):
        port = self.open_port()
        self.write_host(port=port, extra="remote_command = /usr/local/sbin/unlock-root")
        result = self.unlock()
        self.assertEqual(self.calls("ssh")[0]["argv"], unlock_argv(port, command="/usr/local/sbin/unlock-root"))
        self.assertEqual(result.returncode, 5)  # the server of the stub has no such command
        self.assertEqual(self.lines(result)[-2:], [
            "kaltstart: ssh: sh: 1: /usr/local/sbin/unlock-root: not found",
            "kaltstart: the server did not take the passphrase (remote exit status 127, no unlock prompt seen): it was "
            "probably never tested; see the remote message above and try again"])

    def test_token_option_selects_the_credential(self):
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\ndevice = /dev/hidraw5\n"
                          f"[token spare]\ncredential_id = {OTHER_CRED_ID}\ndevice = /dev/hidraw6\n"
                          f"[host srv]\nhost = 127.0.0.1\nport = {self.open_port()}\nsalt = {SALT}\ntoken = main\n")
        self.assertEqual(self.unlock("--token", "spare").returncode, 0)
        self.assertEqual(self.ssh_stdin(0), expected_secret(credential_id=OTHER_CRED_ID))
        self.assertEqual(self.calls("fido2-assert")[0]["argv"][-1], "/dev/hidraw6")
        self.assertEqual(self.unlock("--device", "/dev/hidraw8").returncode, 0)
        self.assertEqual(self.ssh_stdin(1), SECRET)
        self.assertEqual(self.calls("fido2-assert")[1]["argv"][-1], "/dev/hidraw8")

    # ------------------------------------------- evaluation of the sessions

    def test_two_prompts(self):
        self.write_host(port=self.open_port(), extra="prompts = 2")
        result = self.unlock()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["stdin"] for call in self.calls("ssh")], [SECRET, SECRET])
        self.assertEqual(len(self.calls("fido2-assert")), 1)  # one touch for both prompts
        lines = self.lines(result)
        self.assertIn("kaltstart: sending the passphrase to 127.0.0.1 (submission 1 of at most 2)", lines)
        self.assertIn("kaltstart: sending the passphrase to 127.0.0.1 (submission 2 of at most 2)", lines)
        self.assertEqual(lines[-1], "kaltstart: passphrase accepted (2 submissions)")

    def test_stops_when_no_further_device_is_waiting(self):
        # "prompts" is an upper limit: two devices ask, the third session shows no prompt.
        self.write_host(port=self.open_port(), extra="prompts = 5")
        result = self.unlock(env={"STUB_SSH_PROMPTS": "2"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls("ssh")), 3)
        self.assertEqual(self.lines(result)[-2:], ["kaltstart: no further device is waiting for a passphrase",
                                                   "kaltstart: passphrase accepted (2 submissions)"])

    def test_no_waiting_device_means_the_passphrase_was_not_tested(self):
        # cryptroot-unlock exits 0 at once, without a prompt, when no device is locked.
        self.write_host(port=self.open_port(), extra=f"booted_port = {self.open_port()}")
        result = self.unlock(env={"STUB_SSH_PROMPTS": "0"})
        self.assertEqual(result.returncode, 5)
        self.assertEqual(self.lines(result)[-1], "kaltstart: no device was waiting for a passphrase: the server did not "
                                                 "test the passphrase (it may have been unlocked by other means)")
        self.assertNotIn(b"passphrase accepted", result.stderr)
        self.assertNotIn(b"is up", result.stderr)

    def test_rejected_passphrase_is_exit_5(self):
        self.write_host(port=self.open_port())
        result = self.unlock(env={"STUB_SSH_RCS": "1"})
        self.assertEqual(result.returncode, 5)
        self.assertEqual(self.lines(result)[-3:], [
            "kaltstart: ssh: cryptsetup: cryptsetup failed, bad password or options?",
            "kaltstart: remote: Please unlock disk root_crypt",
            "kaltstart: passphrase rejected by the server (remote exit status 1)"])

    def test_rejection_is_not_masked_by_the_booted_port(self):
        self.write_host(port=self.open_port(), extra=f"booted_port = {self.open_port()}")
        result = self.unlock(env={"STUB_SSH_RCS": "1"})
        self.assertEqual(result.returncode, 5)
        self.assertNotIn(b"is up", result.stderr)

    def test_prompts_stop_at_the_first_rejection(self):
        self.write_host(port=self.open_port(), extra="prompts = 3")
        result = self.unlock(env={"STUB_SSH_RCS": "0,1,0"})
        self.assertEqual(result.returncode, 5)
        self.assertEqual(len(self.calls("ssh")), 2)
        self.assertEqual(self.lines(result)[-1], "kaltstart: passphrase rejected by the server (remote exit status 1) "
                                                 "after 1 accepted submission(s)")

    def test_exit_without_unlock_prompt_is_not_called_a_rejection(self):
        # cryptroot-unlock exits 1 before it reads the passphrase, e.g. on its askpass timeout.
        self.write_host(port=self.open_port())
        result = self.unlock(env={"STUB_SSH_RCS": "1", "STUB_SSH_PROMPTS": "0"})
        self.assertEqual(result.returncode, 5)
        self.assertEqual(self.lines(result)[-2:], [
            "kaltstart: ssh: Error: Timeout reached while waiting for askpass.",
            "kaltstart: the server did not take the passphrase (remote exit status 1, no unlock prompt seen): it was "
            "probably never tested; see the remote message above and try again"])
        self.assertNotIn(b"rejected", result.stderr)

    def test_no_further_prompt_after_an_accepted_submission_is_not_a_success(self):
        # A device is still locked, but the initramfs does not ask for its passphrase.
        self.write_host(port=self.open_port(), extra="prompts = 2")
        result = self.unlock(env={"STUB_SSH_RCS": "0,1", "STUB_SSH_PROMPTS": "1"})
        self.assertEqual(result.returncode, 5)
        self.assertEqual(self.lines(result)[-2:], [
            "kaltstart: the server did not ask for another passphrase (remote exit status 1) after 1 accepted "
            "submission(s)",
            CANNOT_TELL])

    def test_no_further_prompt_is_decided_by_the_start_of_the_system(self):
        self.write_host(port=self.open_port(), extra=f"prompts = 2\nbooted_port = {self.open_port()}")
        result = self.unlock(env={"STUB_SSH_RCS": "0,1", "STUB_SSH_PROMPTS": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"the server did not ask for another passphrase", result.stderr)
        self.assertIn(b"127.0.0.1 is up", result.stderr)

    def test_transport_failure_before_the_prompt_fails_at_once(self):
        # Host key mismatch, refused connection, rejected key: nothing was delivered, so an
        # open booted port must not turn this into a success and nothing waits for a start.
        port = self.open_port()
        self.write_host(port=port, extra=f"booted_port = {self.open_port()}")
        for status in ("255", "-9"):  # ended by ssh itself, or ssh ended by a signal
            with self.subTest(status=status):
                result = self.run_cli("unlock", "srv", "--wait", "0", "--boot-timeout", "600",
                                      env={"STUB_SSH_RCS": status})
                self.assertEqual(result.returncode, 4)
                self.assertEqual(self.lines(result)[-1], f"kaltstart: ssh failed (exit status {status}) before the server "
                                 "asked for the passphrase: connection, host key or authentication problem")
                self.assertNotIn(b"is up", result.stderr)
        self.assertIn(f"kaltstart: ssh: ssh: connect to host 127.0.0.1 port {port}: Connection refused".encode(),
                      self.unlock(env={"STUB_SSH_RCS": "255"}).stderr)

    def test_run_that_this_program_ended_names_the_reason(self):
        # Ended after SESSION_LIMIT: not a connection, host key or authentication problem.
        self.write_host(port=self.open_port())
        reply = cli.Reply(-signal.SIGKILL, b"", b"", "no result within 300 s")
        with mock.patch.object(cli, "ssh_run", return_value=reply):
            status, _, err = self.run_main("unlock", "srv", "--wait", "0", "--boot-timeout", "0")
        self.assertEqual(status, 4)
        self.assertEqual(err.splitlines()[-1], f"kaltstart: ssh failed (exit status {-signal.SIGKILL}) before the server "
                         "asked for the passphrase: no result within 300 s")

    def test_undelivered_submission_is_exit_4_while_the_initramfs_still_answers(self):
        port = self.open_port()
        self.write_host(port=port, extra="prompts = 3")
        result = self.unlock(env={"STUB_SSH_RCS": "0,255"})
        self.assertEqual(result.returncode, 4)
        self.assertEqual(len(self.calls("ssh")), 2)
        self.assertEqual(self.lines(result)[-1], "kaltstart: submission 2 could not be delivered (ssh exit status 255) "
                         f"after 1 accepted submission(s), although 127.0.0.1 port {port} still answers")

    def test_initramfs_gone_after_an_accepted_submission(self):
        # Behind a jump host nothing can be probed: a session that fails then means that the start went on.
        self.write_host(port=self.closed_port(), extra="prompts = 3\nprobe = no")
        result = self.run_cli("unlock", "srv", env={"STUB_SSH_RCS": "0,255"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls("ssh")), 2)
        self.assertEqual(self.lines(result)[-2:], ["kaltstart: the initramfs no longer answers: it has moved on",
                                                   "kaltstart: passphrase accepted"])

    def close_port_during_session(self, number, extra, env):
        """Run unlock against a port that closes while the session with this number (from 0) runs."""
        port, close = self.closable_port()
        self.write_host(port=port, extra=extra)
        env = dict(env, STUB_SSH_HANG_MATCH="cryptroot-unlock", STUB_SSH_HANG_SKIP=str(number))
        proc = self.start_cli("unlock", "srv", "--wait", "0", env=env)
        self.wait_for_call(proc, "ssh", "cryptroot-unlock", start=number)
        close()
        self.release()
        status, stderr = self.finish(proc)
        return port, status, stderr.decode().splitlines()

    def test_closed_initramfs_port_ends_the_submissions(self):
        # The only device was opened and the start goes on: no further session is tried.
        port, status, lines = self.close_port_during_session(0, "prompts = 3", {})
        self.assertEqual(status, 0, lines)
        self.assertEqual(len(self.calls("ssh")), 1)
        self.assertEqual(lines[-2:], [f"kaltstart: 127.0.0.1 port {port} is closed: the initramfs has moved on",
                                      "kaltstart: passphrase accepted"])

    def test_session_that_fails_while_the_initramfs_goes_away(self):
        _, status, lines = self.close_port_during_session(1, "prompts = 3", {"STUB_SSH_RCS": "0,255"})
        self.assertEqual(status, 0, lines)
        self.assertEqual(len(self.calls("ssh")), 2)
        self.assertEqual(lines[-2:], ["kaltstart: the initramfs no longer answers: it has moved on",
                                      "kaltstart: passphrase accepted"])

    def test_lost_session_after_delivery_is_decided_by_the_start_of_the_system(self):
        # The passphrase was delivered (the unlock prompt was seen), then the session died.
        for status in ("255", "-9"):
            with self.subTest(status=status):
                env = {"STUB_SSH_RCS": status, "STUB_SSH_STDOUT": PROMPT}
                self.write_host(port=self.open_port(), extra=f"booted_port = {self.open_port()}")
                result = self.unlock(env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"kaltstart: the ssh connection was lost (exit status {status}) after the passphrase was "
                              "delivered\n".encode(), result.stderr)
                self.assertNotIn(b"passphrase accepted", result.stderr)
                self.assertIn(b"kaltstart: 127.0.0.1 is up (port ", result.stderr)

                port = self.closed_port()
                self.write_host(port=self.open_port(), extra=f"booted_port = {port}")
                result = self.unlock(env=env)
                self.assertEqual(result.returncode, 4)
                self.assertEqual(self.lines(result)[-1], f"kaltstart: 127.0.0.1 port {port} did not open within 0 s, and "
                                 f"the ssh connection was lost (exit status {status}) after the passphrase was delivered")

                self.write_host(port=self.open_port())
                result = self.unlock(env=env)
                self.assertEqual(result.returncode, 4)
                self.assertEqual(self.lines(result)[-1], CANNOT_TELL)

    def test_lost_session_on_a_later_prompt(self):
        self.write_host(port=self.open_port(), extra=f"prompts = 2\nbooted_port = {self.open_port()}")
        result = self.unlock(env={"STUB_SSH_RCS": "0,255", "STUB_SSH_STDOUT": PROMPT})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"kaltstart: the ssh connection was lost (exit status 255) after the passphrase was delivered "
                      b"after 1 accepted submission(s)\n", result.stderr)

    def test_slow_cryptsetup_is_not_called_a_rejection(self):
        # cryptroot-unlock waits ten seconds for cryptsetup and then exits 1; the device may still open.
        env = {"STUB_SSH_RCS": "1", "STUB_SSH_STDERR": GAVE_UP}
        self.write_host(port=self.open_port(), extra=f"booted_port = {self.open_port()}")
        result = self.unlock(env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b"rejected", result.stderr)
        self.assertIn(b"kaltstart: cryptroot-unlock stopped waiting for cryptsetup before the result was known\n",
                      result.stderr)
        self.assertIn(b"is up", result.stderr)

        port = self.closed_port()
        self.write_host(port=self.open_port(), extra=f"booted_port = {port}")
        result = self.unlock(env=env)
        self.assertEqual(result.returncode, 5)
        self.assertEqual(self.lines(result)[-1], f"kaltstart: 127.0.0.1 port {port} did not open within 0 s, and "
                         "cryptroot-unlock stopped waiting for cryptsetup before the result was known")

        self.write_host(port=self.open_port())
        result = self.unlock(env=env)
        self.assertEqual(result.returncode, 5)
        self.assertNotIn(b"rejected", result.stderr)
        self.assertEqual(self.lines(result)[-1], CANNOT_TELL)

    # ----------------------------------------------- start of the system

    def test_booted_port_confirms_the_start(self):
        booted = self.open_port()
        self.write_host(port=self.open_port(), extra=f"booted_port = {booted}")
        result = self.unlock()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(result)[-3:], ["kaltstart: passphrase accepted",
                                                   f"kaltstart: waiting for 127.0.0.1 port {booted}",
                                                   f"kaltstart: 127.0.0.1 is up (port {booted} is open)"])

    def test_booted_port_never_opens_is_exit_6(self):
        booted = self.closed_port()
        self.write_host(port=self.open_port(), extra=f"booted_port = {booted}")
        result = self.unlock()
        self.assertEqual(result.returncode, 6)
        self.assertEqual(self.lines(result)[-1], f"kaltstart: 127.0.0.1 port {booted} did not open within 0 s")

    def test_confirmation_is_skipped_where_the_initramfs_itself_would_answer(self):
        # Same machine, same port: the open port would be that of the initramfs and prove nothing.
        port = self.open_port()
        names = ["127.0.0.1"]
        if "127.0.0.1" in {info[4][0] for info in socket.getaddrinfo("localhost", None)}:
            names.append("localhost")  # another name of the same machine
        for name in names:
            with self.subTest(admin_host=name):
                self.write_host(port=port, extra=f"booted_port = {port}\nadmin_host = {name}")
                result = self.unlock()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.lines(result)[-1], "kaltstart: passphrase accepted")
                # And an outcome that only the start could decide stays undecided.
                result = self.unlock(env={"STUB_SSH_RCS": "255", "STUB_SSH_STDOUT": PROMPT})
                self.assertEqual(result.returncode, 4)
                self.assertEqual(self.lines(result)[-1], CANNOT_TELL)

    def two_address_config(self, port, booted):
        """Initramfs on 127.0.0.2, running system on 127.0.0.1: two DHCP leases for one machine."""
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\ndevice = /dev/hidraw5\n"
                          f"[host srv]\nhost = 127.0.0.2\nport = {port}\n"
                          f"salt = {SALT}\nadmin_host = 127.0.0.1\nbooted_port = {booted}\n")

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs a second loopback address (127.0.0.2)")
    def test_start_is_confirmed_on_the_address_of_the_running_system(self):
        # The booted port is open on admin_host only, not on the initramfs address.
        self.two_address_config(self.open_port("127.0.0.2"), self.open_port("127.0.0.1"))
        result = self.unlock()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"kaltstart: 127.0.0.1 is up", result.stderr)
        self.assertEqual(self.calls("ssh")[0]["destination"], "root@127.0.0.2")

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs a second loopback address (127.0.0.2)")
    def test_same_port_on_another_address_still_confirms(self):
        port = self.open_port("127.0.0.2", "127.0.0.1")
        self.two_address_config(port, port)
        result = self.unlock()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"kaltstart: 127.0.0.1 is up", result.stderr)

    def test_probe_no_skips_every_tcp_probe(self):
        # A host behind a jump host: neither the initramfs port nor booted_port is reachable directly.
        port = self.closed_port()
        self.write_host(port=port, extra=f"probe = no\nbooted_port = {self.closed_port()}")
        result = self.run_cli("unlock", "srv")  # the default time limits: nothing must wait
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(result), [f"kaltstart: not probing 127.0.0.1 port {port} (probe = no)", ASKING,
                                              "kaltstart: sending the passphrase to 127.0.0.1",
                                              "kaltstart: ssh: cryptsetup: root_crypt set up successfully",
                                              "kaltstart: remote: Please unlock disk root_crypt",
                                              "kaltstart: passphrase accepted"])
        self.assertEqual(self.ssh_stdin(0), SECRET)

    def test_probe_no_and_a_failing_ssh_is_exit_4(self):
        self.write_host(port=self.closed_port(), extra=f"probe = no\nbooted_port = {self.open_port()}")
        result = self.unlock(env={"STUB_SSH_RCS": "255"})
        self.assertEqual(result.returncode, 4)
        self.assertIn(b"kaltstart: ssh failed (exit status 255) before the server asked for the passphrase", result.stderr)
        # The open booted port is not asked either: what only the start could decide stays undecided.
        result = self.unlock(env={"STUB_SSH_RCS": "255", "STUB_SSH_STDOUT": PROMPT})
        self.assertEqual(result.returncode, 4)
        self.assertIn(b"kaltstart: cannot tell whether the server was unlocked", result.stderr)
        self.assertNotIn(b"is up", result.stderr)

    # ------------------------------------------------- before the server

    def test_port_never_opens_is_exit_6(self):
        port = self.closed_port()
        self.write_host(port=port)
        result = self.unlock()
        self.assertEqual(result.returncode, 6)
        self.assertEqual(self.lines(result), [f"kaltstart: waiting for 127.0.0.1 port {port}",
                                              f"kaltstart: 127.0.0.1 port {port} did not open within 0 s"])
        self.assertEqual(self.calls(), [])

    def test_host_that_cannot_be_resolved_is_named(self):
        self.write_config(f"[token main]\ncredential_id = {CRED_ID}\ndevice = /dev/hidraw5\n"
                          f"[host srv]\nhost = srv01.example.net\nsalt = {SALT}\n")
        unknown = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        with mock.patch.object(cli.socket, "getaddrinfo", side_effect=unknown):
            status, _, err = self.run_main("unlock", "srv", "--wait", "0")
        self.assertEqual(status, 6)
        self.assertEqual(err.splitlines()[-1], "kaltstart: srv01.example.net cannot be resolved (Name or service not known)")
        self.assertEqual(self.calls(), [])

    def test_missing_programs_are_reported_before_the_wait(self):
        # The port is closed and the time limit long: a run that waits first shows itself by the wrong exit status.
        self.write_host(port=self.closed_port(), device=None)
        for name, status, message in (("fido2-token", 3, b"fido2-token not found in PATH (install fido2-tools)"),
                                      ("fido2-assert", 3, b"fido2-assert not found in PATH (install fido2-tools)"),
                                      ("ssh", 4, b"ssh not found in PATH")):
            self.remove_stub(name)
            with self.subTest(missing=name):
                result = self.run_cli("unlock", "srv", "--wait", "3")
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stderr, b"kaltstart: " + message + b"\n")
        self.assertEqual(self.calls(), [])

    def test_fido2_token_is_not_needed_for_a_configured_device(self):
        self.write_host(port=self.open_port(), device="/dev/hidraw5")
        self.remove_stub("fido2-token")
        self.assertEqual(self.unlock().returncode, 0)
        self.write_host(port=self.open_port(), device=None)
        self.assertEqual(self.unlock("--device", "/dev/hidraw5").returncode, 0)

    def test_unusable_token_output_never_reaches_the_server(self):
        self.write_host(port=self.open_port(), device=None)
        for env in ({"STUB_ASSERT_MODE": "truncated"}, {"STUB_ASSERT_MODE": "fail"}, {"STUB_TOKEN_LIST": ""}):
            with self.subTest(env=env):
                self.assertEqual(self.unlock(env=env).returncode, 3)
        self.assertEqual(self.calls("ssh"), [])

    def test_hostile_host_strings_never_reach_ssh(self):
        port = self.open_port()
        for host, user, key in (("-oProxyCommand=evil", "root", "host"), ("127.0.0.1 -oProxyCommand=evil", "root", "host"),
                                ("127.0.0.1;id", "root", "host"), ("127.0.0.1", "-lroot", "user"),
                                ("127.0.0.1", "root -oProxyCommand=evil", "user")):
            with self.subTest(host=host, user=user):
                self.write_config(f"[token main]\ncredential_id = {CRED_ID}\n"
                                  f"[host srv]\nhost = {host}\nuser = {user}\nport = {port}\nsalt = {SALT}\n")
                result = self.unlock()
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"kaltstart: [host srv] {key}: invalid ".encode(), result.stderr)
        self.assertEqual(self.calls(), [])

    # ------------------------------------------------------------ output

    def test_remote_output_is_escaped(self):
        self.write_host(port=self.open_port())
        result = self.unlock(env={"STUB_SSH_STDOUT": PROMPT + "evil \x1b[2J\x07 output\n",
                                  "STUB_SSH_STDERR": "evil \x1b[2J\x07 errors\nbad \udcff byte\n"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"kaltstart: remote: evil \\x1b[2J\\x07 output\n", result.stderr)
        self.assertIn(b"kaltstart: ssh: evil \\x1b[2J\\x07 errors\n", result.stderr)
        self.assertIn("kaltstart: ssh: bad \ufffd byte\n".encode(), result.stderr)
        self.assertNotIn(b"\x1b", result.stderr)
        self.assertNotIn(b"\x07", result.stderr)

    # ----------------------------------------------------------- signals

    def test_sigint_sigterm_sighup_and_sigquit_end_the_session_and_the_program(self):
        self.write_host(port=self.open_port())
        for name in SIGNAL_NAMES:
            with self.subTest(signal=name):
                seen = len(self.calls("ssh"))
                proc = self.start_cli("unlock", "srv", "--wait", "0", ignored=(),
                                      env={"STUB_SSH_HANG_MATCH": "cryptroot-unlock"})
                call = self.wait_for_call(proc, "ssh", "cryptroot-unlock", start=seen)
                self.assertEqual(call["ignored"], [])
                proc.send_signal(getattr(signal, name))
                status, stderr = self.finish(proc)
                self.assertEqual(status, 130, stderr)
                self.assertEqual(stderr.decode().splitlines()[-1], "kaltstart: interrupted")
                # ssh does not go on with the passphrase after the program has given up.
                self.assert_ended_by_the_program(call)
                self.assertEqual(len(self.calls("ssh")), seen + 1)

    def test_sighup_or_sigterm_ignored_at_the_start_stays_ignored(self):
        # As under nohup: the run goes on.
        self.write_host(port=self.open_port())
        for name in ("SIGHUP", "SIGTERM"):
            with self.subTest(signal=name):
                seen = len(self.calls("ssh"))
                proc = self.start_cli("unlock", "srv", "--wait", "0", ignored=(name,),
                                      env={"STUB_SSH_HANG_MATCH": "cryptroot-unlock", "STUB_SSH_HANG_SKIP": str(seen)})
                call = self.wait_for_call(proc, "ssh", "cryptroot-unlock", start=seen)
                self.assertEqual(call["ignored"], [name])  # ssh inherits the disposition
                proc.send_signal(getattr(signal, name))
                self.release()
                status, stderr = self.finish(proc)
                self.assertEqual(status, 0, stderr)
                self.assertEqual(stderr.decode().splitlines()[-1], "kaltstart: passphrase accepted")
                os.remove(os.path.join(self.stub, "release"))
