# SPDX-License-Identifier: GPL-2.0-only
"""Shared test helpers: the program as a module, stub executables, a test directory and ways to run the program.

Nothing here touches the real home directory, a real token or the network.
The executables on PATH are launchers for tests/stub.py and nothing else;
that file describes what the stubs record and how they are steered. During
a test the environment of the test process is replaced as well, so that
code of the program that is called directly finds the same surroundings as
the program started as a process.
"""

import ast
import base64
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import py_compile
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import stub
from stub import DEVICE_LINE, INSTALLATION_KEY, STUB_CRED_ID  # noqa: F401 (passed on to the test modules)

# Taken from the environment of the caller here, because the test cases replace the environment.
CALLER_PATH = os.environ.get("PATH", os.defpath)
tempfile.gettempdir()  # the module keeps the directory that it finds now
TESTS = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(os.path.dirname(TESTS), "kaltstart")
STUB = os.path.join(TESTS, "stub.py")
STUB_NAMES = ("fido2-assert", "fido2-cred", "fido2-token", "ssh", "ssh-keygen")

CRED_ID = base64.b64encode(b"test-credential-id-" * 3).decode()
OTHER_CRED_ID = base64.b64encode(b"other-credential-id-" * 3).decode()
SALT = base64.b64encode(bytes(range(32))).decode()
OTHER_SALT = base64.b64encode(bytes(range(32, 64))).decode()
SERVER_DEVICES = ("/dev/sda3", "/dev/sdb3")

# The options that the program puts on every ssh command line, written out
# here and not taken from the program: forced ones before everything that
# can be configured, further ones for the initramfs, and the defaults that
# follow the configured options.
FORCED = ["-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "VerifyHostKeyDNS=no",
          "-o", "ControlMaster=no", "-o", "ControlPath=none",
          "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes"]
INITRAMFS = ["-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]
DEFAULTS = ["-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3"]
SIGNAL_NAMES = ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT")
TIMEOUT = 60  # seconds after which a run of the program counts as stuck

# Sets the disposition of the signals named in its first argument (ignored
# for those that the second argument names as well, the default for the
# others), then becomes the command that follows.
LAUNCHER = """\
import os, signal, sys
for name in sys.argv[1].split(","):
    signal.signal(getattr(signal, name), signal.SIG_IGN if name in sys.argv[2].split(",") else signal.SIG_DFL)
os.execv(sys.argv[3], sys.argv[3:])
"""


def expected_secret(credential_id=CRED_ID, salt=SALT, rp_id="kaltstart", pin=True):
    """The passphrase that the fido2-assert stub derives for these inputs (44 ASCII bytes)."""
    return stub.hmac_secret(credential_id, salt, rp_id, pin).encode("ascii")


def load_cli():
    """Import the program (a file without .py suffix) as a module, without writing bytecode."""
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader = importlib.machinery.SourceFileLoader("kaltstart_cli", CLI)
        spec = importlib.util.spec_from_loader("kaltstart_cli", loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules["kaltstart_cli"] = module
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


cli = load_cli()


def process_ended(pid):
    """True if no process with this ID runs any more."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    try:
        # An orphan that was handed to this process and has exited.
        return os.waitpid(pid, os.WNOHANG)[0] == pid
    except ChildProcessError:
        return False


class IsolatedTestCase(unittest.TestCase):
    """A test whose process environment holds nothing of the caller's: HOME and PATH point nowhere."""

    def isolate(self, environment):
        patcher = mock.patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def setUp(self):
        self.isolate({"HOME": "/nonexistent/home", "PATH": "/nonexistent/bin"})

    @contextlib.contextmanager
    def assert_failure(self, code, *fragments, message=None, start=None):
        """The block raises the Failure of the program with this exit status.

        Its message holds the FRAGMENTS, equals MESSAGE and begins with
        START, as far as these are given, and is fit for a terminal: one
        line without control characters.
        """
        failure = None
        try:
            yield
        except cli.Failure as exc:
            failure = exc
        try:
            self.assertIsNotNone(failure, "the program did not fail")
            text = str(failure)
            self.assertEqual(failure.code, code, text)
            for fragment in fragments:
                self.assertIn(fragment, text)
            if message is not None:
                self.assertEqual(text, message)
            if start is not None:
                self.assertEqual(text[:len(start)], start)
            self.assertIsNone(cli.CONTROL_RE.search(text), repr(text))
        except AssertionError as problem:
            raise problem from None  # reported without the Failure, which was expected


class CliTestCase(IsolatedTestCase):
    """A test directory with HOME, XDG_CONFIG_HOME, TMPDIR, a working directory and the stubs as the only PATH.

    The directory "stub" holds what the stubs keep: their log and the
    modelled server, which starts with the LUKS devices SERVER_DEVICES.
    """

    bytecode = None  # the compiled stub, made by the first test that installs it

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kaltstart-test-")
        self.addCleanup(self.remove_directory)
        if os.statvfs(self.tmp).f_flag & getattr(os, "ST_NOEXEC", 0):
            self.skipTest("the temporary directory does not permit executables (noexec); set TMPDIR to one that does")
        self.home, self.xdg, self.bin, self.stub, self.tmpdir, self.cwd = (
            os.path.join(self.tmp, name) for name in ("home", "xdg", "bin", "stub", "tmp", "cwd"))
        for directory in (self.home, self.xdg, self.bin, self.stub, self.tmpdir, self.cwd):
            os.mkdir(directory)
        self.install_stubs(STUB_NAMES)
        for device in SERVER_DEVICES:
            self.add_device(device)
        self.config = os.path.join(self.xdg, "kaltstart", "config.ini")
        self.env = {"PATH": self.bin, "HOME": self.home, "XDG_CONFIG_HOME": self.xdg, "STUB_DIR": self.stub,
                    "TMPDIR": self.tmpdir}
        self.isolate(self.env)
        patcher = mock.patch.object(tempfile, "tempdir", self.tmpdir)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sessions = []
        self.addCleanup(self.end_sessions)
        self.addCleanup(self.check_stubs)

    def remove_directory(self):
        for directory, names, _ in os.walk(self.tmp):
            for name in names:
                os.chmod(os.path.join(directory, name), 0o700)
        shutil.rmtree(self.tmp)

    def check_stubs(self):
        """Fail the test if a stub met a command line that it does not model, or failed itself."""
        try:
            with open(os.path.join(self.stub, "problems.log"), encoding="utf-8") as handle:
                self.fail("a stub could not imitate the real program:\n" + handle.read())
        except FileNotFoundError:
            pass

    def plain_directory_needed(self):
        """Skip a test that keeps identity or known_hosts files in the test directory if its path rules that out."""
        if cli.UNSAFE_PATH_RE.search(self.tmp):
            self.skipTest("the path of the temporary directory holds characters that the program refuses "
                          "in identity and known_hosts paths")

    # ---------------------------------------------------------------- stubs

    def install_stubs(self, names):
        """Put a launcher for each stub into the PATH directory.

        The launchers are shell scripts, because a "#!" line could not
        name an interpreter whose path holds a blank. They run the stub
        from its bytecode: compiling the source anew for each of the
        several hundred stub runs of the suite would take seconds.
        """
        compiled = os.path.join(self.stub, "stub.pyc")
        if CliTestCase.bytecode is None:
            py_compile.compile(STUB, cfile=compiled, doraise=True)
            with open(compiled, "rb") as handle:
                CliTestCase.bytecode = handle.read()
        with open(compiled, "wb") as handle:
            handle.write(CliTestCase.bytecode)
        for name in names:
            path = os.path.join(self.bin, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexec %s -I %s %s \"$@\"\n"
                             % (shlex.quote(sys.executable), shlex.quote(compiled), name))
            os.chmod(path, 0o755)

    def remove_stub(self, name):
        os.remove(os.path.join(self.bin, name))

    def calls(self, tool=None):
        """Recorded runs of the stubs, oldest first; of one stub if TOOL is given."""
        try:
            with open(os.path.join(self.stub, "calls.log"), encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except FileNotFoundError:
            return []
        records = []
        for line in lines:
            name, _, text = line.partition(" ")
            if tool in (None, name):
                records.append(dict(ast.literal_eval(text), tool=name))
        return records

    def ssh_stdin(self, index):
        return self.calls("ssh")[index]["stdin"]

    def remote_commands(self, start=0):
        """The remote command of every ssh run, each with "-t" or "-T" for a session with or without a terminal."""
        return [("-t" if call["terminal"] else "-T", call["command"]) for call in self.calls("ssh")[start:]]

    def wait_for_call(self, proc, tool, text, start=0):
        """Wait until the program PROC has started TOOL with TEXT in one of its arguments, and return the record.

        START is the number of runs of TOOL that are on record already.
        """
        deadline = time.monotonic() + TIMEOUT
        while True:
            for call in self.calls(tool)[start:]:
                if any(text in argument for argument in call["argv"]):
                    return call
            if proc.poll() is not None:
                self.fail(f"the program ended with status {proc.returncode} without a run of {tool} with {text!r}:\n"
                          + proc.stderr.read().decode("utf-8", "replace"))
            self.assertLess(time.monotonic(), deadline, f"no run of {tool} with {text!r} was recorded")
            time.sleep(0.01)

    def release(self):
        """Let the ssh runs go on that STUB_SSH_HANG_MATCH blocks."""
        with open(os.path.join(self.stub, "release"), "w", encoding="ascii"):
            pass

    def assert_ended_by_the_program(self, call):
        """The stub run of this record was ended by the program. To be called once the program has exited.

        A blocked stub that outlives the program either still runs, or it
        has found itself orphaned and has noted that.
        """
        self.assertTrue(process_ended(call["pid"]), "the stub still runs although the program has exited")
        self.assertFalse(os.path.exists(os.path.join(self.stub, "orphans.log")),
                         "the stub was still running when the program exited")

    def assert_no_trace_of(self, secret):
        """The passphrase is in no argument and no environment of a stub run and in no file of the test directory.

        The directory of the stubs is left out: its log holds the standard
        input of ssh, and the modelled server holds what was sent to it.
        """
        text = secret.decode("ascii")
        calls = self.calls()
        self.assertTrue(calls)
        for call in calls:
            for argument in call["argv"]:
                self.assertNotIn(text, argument, call["tool"])
            for name, value in call["env"].items():
                self.assertNotIn(text, name + "=" + value, call["tool"])
        for directory, names, files in os.walk(self.tmp):
            if directory == self.stub:
                del names[:]
                continue
            for name in files:
                with open(os.path.join(directory, name), "rb") as handle:
                    self.assertNotIn(secret, handle.read(), os.path.join(directory, name))
        self.assertEqual(os.listdir(self.tmpdir), [])
        self.assertEqual(os.listdir(self.cwd), [])

    # --------------------------------------------------- the modelled server

    def add_device(self, device, *passphrases):
        """A LUKS device of the server: keyslot 0 holds INSTALLATION_KEY, the next ones the given passphrases."""
        os.makedirs(stub.server_path(self.stub, "luks", device))
        for slot, passphrase in enumerate((INSTALLATION_KEY,) + passphrases):
            with open(stub.server_path(self.stub, "luks", device, slot), "wb") as handle:
                handle.write(passphrase)

    def add_keyslot(self, device, passphrase):
        """Put a passphrase into the next free keyslot of a LUKS device of the server."""
        with open(stub.server_path(self.stub, "luks", device, len(self.keyslots(device))), "wb") as handle:
            handle.write(passphrase)

    def keyslots(self, device):
        """The passphrases in the keyslots of a LUKS device of the server, by keyslot number."""
        directory = stub.server_path(self.stub, "luks", device)
        slots = []
        for slot in sorted(os.listdir(directory), key=int):
            with open(os.path.join(directory, slot), "rb") as handle:
                slots.append(handle.read())
        return slots

    def add_file(self, name, content, mode=0o600):
        """A file of the server."""
        os.makedirs(stub.server_path(self.stub, "files"), exist_ok=True)
        with open(stub.server_path(self.stub, "files", name), "wb") as handle:
            handle.write(content)
        os.chmod(stub.server_path(self.stub, "files", name), mode)

    def server_files(self):
        """Content and mode of every file that exists on the server, by name."""
        files = {}
        for name in stub.server_names(self.stub, "files"):
            path = stub.server_path(self.stub, "files", name)
            with open(path, "rb") as handle:
                files[name] = (handle.read(), os.stat(path).st_mode & 0o777)
        return files

    # -------------------------------------------------------- configuration

    def write_config(self, text, mode=0o600):
        os.makedirs(os.path.dirname(self.config), mode=0o700, exist_ok=True)
        with open(self.config, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(self.config, mode)

    def write_host(self, port=22, extra="", token_extra="", device="/dev/hidraw5"):
        """A configuration with [token main] and [host srv] at 127.0.0.1.

        The token section names its device, which saves the search for it
        (one run of fido2-token) in every test that is not about that
        search. device=None leaves the key out.
        """
        device = f"device = {device}\n" if device else ""
        self.write_config(
            f"[token main]\ncredential_id = {CRED_ID}\n{device}{token_extra}\n"
            f"[host srv]\nhost = 127.0.0.1\nport = {port}\nsalt = {SALT}\n{extra}\n")

    # ------------------------------------------------- running the program

    def start(self, argv, env=None, unset=(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
        """Start a process in the test environment, in a session of its own that ends with the test at the latest."""
        full_env = dict(self.env)
        full_env.update(env or {})
        for name in unset:
            del full_env[name]
        proc = subprocess.Popen(argv, env=full_env, cwd=self.cwd, stdin=stdin, stdout=stdout, stderr=stderr,
                                start_new_session=True)
        self.sessions.append(proc)
        return proc

    def end(self, proc):
        """End a process started by start() and everything it left behind in its session."""
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream:
                stream.close()

    def end_sessions(self):
        while self.sessions:
            self.end(self.sessions.pop())

    def run_cli(self, *args, **options):
        """Run the program with an empty standard input and wait for it."""
        proc = self.start([sys.executable, "-I", CLI] + list(args), **options)
        try:
            out, err = proc.communicate(timeout=TIMEOUT)
        finally:
            self.end(proc)
        return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)

    def start_cli(self, *args, ignored=None, **options):
        """Start the program without waiting for it; finish() does that.

        With IGNORED the termination signals get a defined disposition
        first: ignored for the names given, the default for the others.
        What the test process inherited (for example an ignored SIGHUP
        under nohup) is then not passed on.
        """
        launcher = []
        if ignored is not None:
            launcher = [sys.executable, "-I", "-c", LAUNCHER, ",".join(SIGNAL_NAMES), ",".join(ignored)]
        return self.start(launcher + [sys.executable, "-I", CLI] + list(args), **options)

    def finish(self, proc):
        """Wait for a program started by start_cli(). Returns its exit status and its standard error.

        Processes that the program left behind keep running until the
        test ends, so that the test can look at them.
        """
        _, err = proc.communicate(timeout=TIMEOUT)
        return proc.returncode, err

    def run_main(self, *args, env=None):
        """Call main() of the program in the test process. Returns (exit status, standard output, standard error).

        The signal handlers that main() installs are taken back, and the
        core file size limit of the test process is left alone; the mock
        that stands in for resource.setrlimit is kept as self.setrlimit.
        """
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=True)
        err = io.StringIO()
        handlers = {signum: signal.getsignal(signum) for signum in cli.TERMINATION_SIGNALS}
        try:
            with mock.patch.dict(os.environ, env or {}), mock.patch.object(cli, "VERBOSE", False), \
                    mock.patch.object(cli.resource, "setrlimit") as self.setrlimit, \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = cli.main(list(args))
        finally:
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
        return status, out.buffer.getvalue().decode("utf-8"), err.getvalue()

    # ---------------------------------------------------------------- ports

    def open_port(self, *addresses):
        """A TCP port that accepts connections on 127.0.0.1, or on each of the given loopback addresses."""
        addresses = addresses or ("127.0.0.1",)
        for _ in range(100):
            sockets = [socket.socket() for _ in addresses]
            try:
                sockets[0].bind((addresses[0], 0))
                port = sockets[0].getsockname()[1]
                for sock, address in zip(sockets[1:], addresses[1:]):
                    sock.bind((address, port))  # fails if the port is taken on that address
            except OSError:
                for sock in sockets:
                    sock.close()
                continue
            for sock in sockets:
                sock.listen(64)
                self.addCleanup(sock.close)
            return port
        self.fail("found no port that is free on " + " and ".join(addresses))

    def closable_port(self):
        """An open TCP port on 127.0.0.1 and the function that closes it.

        After the call of that function the port refuses connections. A
        second socket keeps it bound, where the system allows that, so
        that nothing else can take the port before the program has tried it.
        """
        listener = socket.socket()
        self.addCleanup(listener.close)
        address = ("127.0.0.1", 0)
        if hasattr(socket, "SO_REUSEPORT"):
            address = self.reserved_socket(shared=True).getsockname()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        listener.bind(address)
        listener.listen(64)
        return listener.getsockname()[1], listener.close

    def reserved_socket(self, shared=False):
        """A socket bound to a port of 127.0.0.1 that refuses connections until listen() is called on it.

        The port stays bound until the test ends: nothing else can take it
        in the meantime. A SHARED one lets a second socket of the test
        listen on the same port.
        """
        sock = socket.socket()
        if shared and hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("127.0.0.1", 0))
        self.addCleanup(sock.close)
        return sock

    def closed_port(self):
        """A TCP port on 127.0.0.1 that refuses connections."""
        return self.reserved_socket().getsockname()[1]
