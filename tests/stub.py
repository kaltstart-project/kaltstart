# SPDX-License-Identifier: GPL-2.0-only
"""Stand-in for the programs that kaltstart runs: fido2-assert, fido2-cred, fido2-token, ssh and ssh-keygen.

Usage: stub.py NAME [ARGUMENT ...]

support.CliTestCase puts one launcher per NAME into the directory that is
the only entry of PATH. Every run appends a line "NAME RECORD" to
$STUB_DIR/calls.log. RECORD is a Python literal: a dictionary with the
arguments, the environment, the process ID, the core file size limit, the
termination signals that are ignored, the exit status and whatever the
tool adds (ssh: its standard input, the destination, the remote command
and whether a terminal was requested). The exit status is None for a run
that was put on record before it ended: one that blocked, or one that asked
for something on the terminal.

A command line that the real program rejects ends the run with the exit
status of that program (1 for the fido2 tools, 255 for ssh and ssh-keygen).
A command line that the real program accepts but that is not modelled
here, and an error of the stub itself, are noted in $STUB_DIR/problems.log
and end the run with UNMODELLED: no test is meant to pass on a behaviour
that was never imitated.

Environment variables steer the outcome:

    STUB_TOKEN_LIST    fido2-token: output of "-L" (default: DEVICE_LINE)
    STUB_TOKEN_RC      fido2-token: exit status
    STUB_ASSERT_MODE   fido2-assert: ok, fail, empty, garbage, short, truncated or blank-lines
    STUB_CRED_ID       fido2-cred: credential ID that is printed (default: STUB_CRED_ID)
    STUB_CRED_MODE     fido2-cred: "short" prints three lines only
    STUB_CRED_RC       fido2-cred: exit status
    STUB_KEYGEN_RC     ssh-keygen: exit status of the search
    STUB_SSH_*         ssh: see run_ssh
"""

import binascii
import os
import resource
import sys
import time

try:
    # The plain module. "signal" wraps it in enumerations, and building
    # those takes longer than everything that a stub does itself.
    import _signal as signal
except ImportError:
    import signal

UNMODELLED = 97

DEVICE_LINE = "/dev/hidraw5: vendor=0x1234, product=0x5678 (Example FIDO2 Token)\n"
STUB_CRED_ID = "c3R1Yi1jcmVkZW50aWFsLWlkLTAxMjM0NTY3ODk="  # base64 of b"stub-credential-id-0123456789"
# The passphrase in keyslot 0 of a LUKS device of the modelled server.
INSTALLATION_KEY = b"passphrase of the installation"
TERMINATION_SIGNALS = ("SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM")
HANG_LIMIT = 60.0  # seconds after which a blocked run ends on its own


class Stop(Exception):
    """Ends the run. The arguments are the exit status and the text for standard error."""


def unmodelled(what):
    return Stop(UNMODELLED, "stub: %s is not modelled\n" % what)


def b64(raw):
    return binascii.b2a_base64(raw, newline=False).decode("ascii")


def unb64(text):
    """Decode strict, canonical base64. Returns None for anything else."""
    try:
        raw = binascii.a2b_base64(text.encode("ascii"))
    except ValueError:  # includes binascii.Error and UnicodeEncodeError
        return None
    return raw if raw and b64(raw) == text else None


def hmac_secret(credential_id, salt, rp_id, verified):
    """The value that the fido2-assert stub prints as hmac secret (base64 text).

    Like the value of a real token it depends on the credential, on the
    salt, on the relying party ID and on whether the user was verified.
    """
    import hashlib  # here, because few runs need it and every import delays the start
    material = b"\0".join((unb64(credential_id), unb64(salt), rp_id.encode("utf-8"), b"uv" if verified else b"up"))
    return b64(hashlib.sha256(material).digest())


def server_path(directory, kind, name=None, slot=None):
    """Local path that stands for a file (kind "files") or a LUKS device (kind "luks") of the modelled server.

    A file of the server is a local file with the same content and mode. A
    LUKS device is a directory with one file per keyslot, named after the
    keyslot number, that holds the passphrase of that keyslot. Without a
    name the result is the directory that holds all objects of the kind.
    """
    path = os.path.join(directory, "server", kind)
    if name is not None:
        path = os.path.join(path, binascii.hexlify(name.encode("utf-8", "surrogateescape")).decode("ascii"))
    return path if slot is None else os.path.join(path, str(slot))


def server_names(directory, kind):
    """The names of the files or LUKS devices of the modelled server."""
    try:
        encoded = os.listdir(server_path(directory, kind))
    except FileNotFoundError:
        return []
    return sorted(binascii.unhexlify(name).decode("utf-8", "surrogateescape") for name in encoded)


class Call:
    """One run of the stub: its record in the log and its end."""

    def __init__(self, name, arguments):
        self.name = name
        self.directory = os.environ["STUB_DIR"]
        self.parent = os.getppid()
        self.index = self.earlier()
        self.logged = False
        self.record = {
            "argv": arguments,
            "env": dict(os.environ),
            "pid": os.getpid(),
            "core": list(resource.getrlimit(resource.RLIMIT_CORE)),
            "ignored": [name for name in TERMINATION_SIGNALS
                        if signal.getsignal(getattr(signal, name)) == signal.SIG_IGN],
            "status": None,
        }

    def path(self, name):
        return os.path.join(self.directory, name)

    def earlier(self):
        """Number of earlier runs under the same name."""
        try:
            with open(self.path("calls.log"), encoding="utf-8") as handle:
                return sum(line.startswith(self.name + " ") for line in handle)
        except FileNotFoundError:
            return 0

    def count(self, name):
        """Count the runs that reach this point in the file NAME. Returns the number of earlier ones."""
        try:
            with open(self.path(name), encoding="ascii") as handle:
                seen = int(handle.read())
        except FileNotFoundError:
            seen = 0
        with open(self.path(name), "w", encoding="ascii") as handle:
            handle.write(str(seen + 1))
        return seen

    def log(self):
        """Append the record, once, with a single write: a reader never finds half a line."""
        if not self.logged:
            self.logged = True
            line = "%s %r\n" % (self.name, self.record)
            fd = os.open(self.path("calls.log"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)

    def problem(self, text):
        with open(self.path("problems.log"), "a", encoding="utf-8") as handle:
            handle.write("%s %r: %s\n" % (self.name, self.record["argv"], text.strip()))

    def hang(self):
        """Block until $STUB_DIR/release exists.

        The record is written first, without an exit status, so that a
        test can wait for the run. A run whose calling process has gone
        notes that in $STUB_DIR/orphans.log and ends.
        """
        self.log()
        deadline = time.monotonic() + HANG_LIMIT
        while not os.path.exists(self.path("release")):
            if os.getppid() != self.parent:
                with open(self.path("orphans.log"), "a", encoding="ascii") as handle:
                    handle.write("%d %s\n" % (os.getpid(), self.name))
                sys.exit(1)
            if time.monotonic() > deadline:
                sys.exit(1)
            time.sleep(0.02)

    def finish(self, status, out=b"", err=b""):
        """Write the output and end the run. A negative status ends it by that signal."""
        self.record["status"] = status
        self.log()
        sys.stderr.buffer.write(err)
        sys.stderr.buffer.flush()
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        if status < 0:
            if -status != signal.SIGKILL:
                signal.signal(-status, signal.SIG_DFL)  # also where the caller ignores the signal
            os.kill(os.getpid(), -status)
        sys.exit(status)


def parse(arguments, option_string, status, usage):
    """Split a command line the way getopt(3) does with the option string of the real program.

    Returns the options as pairs of name and argument, and the words that
    follow them. An unknown option and a missing argument end the run with
    STATUS. (The getopt module does the same but is slow to import.)
    """
    options, words = [], list(arguments)
    while words and words[0].startswith("-") and words[0] != "-":
        word = words.pop(0)
        if word == "--":
            break
        for position, letter in enumerate(word[1:], start=2):
            index = option_string.find(letter)
            if letter == ":" or index < 0:
                raise Stop(status, "invalid option -- '%s'\nusage: %s\n" % (letter, usage))
            if option_string[index + 1:index + 2] != ":":
                options.append(("-" + letter, ""))
            elif position < len(word):
                options.append(("-" + letter, word[position:]))
                break
            elif words:
                options.append(("-" + letter, words.pop(0)))
            else:
                raise Stop(status, "option requires an argument -- '%s'\nusage: %s\n" % (letter, usage))
    return options, words


# --------------------------------------------------------------------------
# fido2-tools
# --------------------------------------------------------------------------

def read_parameters(call, options, kinds):
    """Read the input of fido2-assert or fido2-cred: one base64 blob or one string per line."""
    path = dict(options).get("-i")
    if path is None:
        text = sys.stdin.read()
    else:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        call.record.update(param_file=path, param_mode=os.stat(path).st_mode & 0o777,
                           dir_mode=os.stat(os.path.dirname(path)).st_mode & 0o777)
    lines = text.split("\n")
    call.record["params"] = lines
    for kind, line in zip(kinds, lines + [""] * len(kinds)):
        if not line or (kind == "blob" and unb64(line) is None):
            raise Stop(1, "%s: input error\n" % call.name)
    return lines


def run_fido2_token(call, arguments):
    """fido2-token -L [-bder] [-k rp_id] [device]: only the plain list of devices is modelled."""
    if arguments[:1] != ["-L"]:
        raise unmodelled("fido2-token without -L as its first argument")
    options, words = parse(arguments[1:], "bdek:r", 1, "fido2-token -L [-bder] [-k rp_id] [device]")
    if words or [name for name, _ in options if name != "-d"]:
        raise unmodelled("a list other than that of the devices")
    return int(os.environ.get("STUB_TOKEN_RC", "0")), os.fsencode(os.environ.get("STUB_TOKEN_LIST", DEVICE_LINE)), b""


def run_fido2_assert(call, arguments):
    """fido2-assert -G [-bdhpruvw] [-t option] [-i input_file] [-o output_file] device"""
    usage = "fido2-assert -G [-bdhpruvw] [-t option] [-i input_file] [-o output_file] device"
    if arguments[:1] == ["-V"]:
        raise unmodelled("fido2-assert -V")
    if arguments[:1] != ["-G"]:
        raise Stop(1, "usage: %s\n" % usage)
    options, words = parse(arguments[1:], "bdhi:o:prt:uvw", 1, usage)
    if len(words) != 1:
        raise Stop(1, "usage: %s\n" % usage)
    flags = {name for name, _ in options}
    if flags & {"-b", "-o", "-r", "-u", "-w"}:
        raise unmodelled("fido2-assert with -b, -o, -r, -u or -w")
    toggles = {}
    for name, value in options:
        if name == "-t":
            key, _, state = value.partition("=")
            if key not in ("up", "uv", "pin") or state not in ("true", "false"):
                raise Stop(1, "fido2-assert: invalid options -t %s\n" % value)
            toggles[key] = state == "true"
    # Input: client data hash, relying party ID, credential ID and, with -h, the hmac salt.
    lines = read_parameters(call, options, ["blob", "string", "blob"] + ["blob"] * ("-h" in flags))
    if "-h" in flags and len(unb64(lines[3])) not in (32, 64):
        raise Stop(1, "fido2-assert: the hmac salt must have 32 or 64 bytes\n")
    mode = os.environ.get("STUB_ASSERT_MODE", "ok")
    if mode == "fail":
        return 1, b"", b""
    if mode == "empty":
        return 0, b"", b""
    # Output: client data hash, relying party ID, authenticator data,
    # signature and, with -h, the hmac secret.
    out = [lines[0], lines[1], b64(b"A" * 37), b64(b"S" * 71)]
    if "-h" in flags:
        verified = "-v" in flags or toggles.get("pin", False) or toggles.get("uv", False)
        secret = hmac_secret(lines[2], lines[3], lines[1], verified)
        if mode == "garbage":
            secret = "this is not base64 at all!"
        elif mode == "short":
            secret = b64(unb64(secret)[:16])
        out.append(secret)
    if mode == "truncated":
        out = out[:1]
    elif mode == "blank-lines":
        out += ["", ""]
    return 0, ("\n".join(out) + "\n").encode("utf-8"), b""


def run_fido2_cred(call, arguments):
    """fido2-cred -M [-bdhqruvw] [-c cred_protect] [-i input_file] [-o output_file] device [type]"""
    usage = "fido2-cred -M [-bdhqruvw] [-c cred_protect] [-i input_file] [-o output_file] device [type]"
    if arguments[:1] == ["-V"]:
        raise unmodelled("fido2-cred -V")
    if arguments[:1] != ["-M"]:
        raise Stop(1, "usage: %s\n" % usage)
    options, words = parse(arguments[1:], "bc:dhi:o:qruvw", 1, usage)
    if len(words) not in (1, 2) or words[1:] not in ([], ["es256"], ["rs256"], ["eddsa"]):
        raise Stop(1, "usage: %s\n" % usage)
    if {name for name, _ in options} & {"-b", "-o", "-q", "-r", "-u", "-w"}:
        raise unmodelled("fido2-cred with -b, -o, -q, -r, -u or -w")
    for name, value in options:
        if name == "-c" and not (value.isascii() and value.isdigit()):
            raise Stop(1, "fido2-cred: -c: invalid argument '%s'\n" % value)
    # Input: client data hash, relying party ID, user name, user ID.
    lines = read_parameters(call, options, ["blob", "string", "string", "blob"])
    # Output: client data hash, relying party ID, format, authenticator data,
    # credential ID, attestation signature, attestation certificate.
    out = [lines[0], lines[1], "packed", b64(b"A" * 164), os.environ.get("STUB_CRED_ID", STUB_CRED_ID),
           b64(b"S" * 71), b64(b"C" * 300)]
    if os.environ.get("STUB_CRED_MODE") == "short":
        out = out[:3]
    return int(os.environ.get("STUB_CRED_RC", "0")), ("\n".join(out) + "\n").encode("utf-8"), b""


# --------------------------------------------------------------------------
# ssh-keygen
# --------------------------------------------------------------------------

def run_ssh_keygen(call, arguments):
    """ssh-keygen -F hostname [-lv] [-f known_hosts_file]: the search for a host key."""
    options, words = parse(arguments, "F:f:lv", 255, "ssh-keygen -F hostname [-lv] [-f known_hosts_file]")
    if "-F" not in dict(options):
        raise unmodelled("ssh-keygen without -F")
    if words:
        raise Stop(255, "Too many arguments.\n")
    status = int(os.environ.get("STUB_KEYGEN_RC", "0"))
    found = ("# Host %s found: line 1\n" % dict(options)["-F"]).encode("utf-8")
    return status, b"" if status else found, b""


# --------------------------------------------------------------------------
# ssh
# --------------------------------------------------------------------------

# From the SYNOPSIS of ssh(1).
SSH_OPTION_STRING = "46AaCfGgKkMNnqsTtVvXxYyB:b:c:D:E:e:F:I:i:J:L:l:m:O:o:P:p:Q:R:S:W:w:"
SSH_USAGE = "ssh [options] destination [command [argument ...]]"
# The keywords of ssh_config(5) that can be given with -o.
SSH_KEYWORDS = frozenset("""
    addkeystoagent addressfamily batchmode bindaddress bindinterface casignaturealgorithms canonicaldomains
    canonicalizefallbacklocal canonicalizehostname canonicalizemaxdots canonicalizepermittedcnames certificatefile
    channeltimeout checkhostip ciphers clearallforwardings compression connecttimeout connectionattempts
    controlmaster controlpath controlpersist dynamicforward enableescapecommandline enablesshkeysign escapechar
    exitonforwardfailure fingerprinthash forkafterauthentication forwardagent forwardx11 forwardx11timeout
    forwardx11trusted gssapiauthentication gssapidelegatecredentials gatewayports globalknownhostsfile
    hashknownhosts hostkeyalgorithms hostkeyalias hostbasedacceptedalgorithms hostbasedauthentication hostname
    ipqos identitiesonly identityagent identityfile ignoreunknown kbdinteractiveauthentication
    kbdinteractivedevices kexalgorithms knownhostscommand localcommand localforward loglevel logverbose macs
    nohostauthenticationforlocalhost numberofpasswordprompts obscurekeystroketiming pkcs11provider
    passwordauthentication permitlocalcommand permitremoteopen port preferredauthentications proxycommand
    proxyjump proxyusefdpass pubkeyacceptedalgorithms pubkeyauthentication rekeylimit remotecommand remoteforward
    requesttty requiredrsasize revokedhostkeys securitykeyprovider sendenv serveralivecountmax
    serveraliveinterval sessiontype setenv stdinnull streamlocalbindmask streamlocalbindunlink
    stricthostkeychecking syslogfacility tcpkeepalive tag tunnel tunneldevice updatehostkeys user
    userknownhostsfile verifyhostkeydns versionaddendum visualhostkey xauthlocation
""".split())


def run_ssh(call, arguments):
    """ssh: the client and, behind it, the server that runs the remote command.

    The client checks its command line; the server is the class Server.
    Steering variables:

    STUB_SSH_RCS             exit statuses of the successive ssh runs that start cryptroot-unlock, separated
                             by commas (the last one is repeated). 255 is a connection that fails before
                             the remote command runs; a negative number is an ssh that is ended by that
                             signal.
    STUB_SSH_PROMPTS         number of ssh runs, counted from the first, in which cryptroot-unlock finds a
                             device that waits for its passphrase (default: all)
    STUB_SSH_FAIL_MATCH      a remote command that contains this text does not run; ssh ends with the status
    STUB_SSH_FAIL_RC         given here instead (default 1; 255 and negative as above), except for the first
    STUB_SSH_FAIL_SKIP       commands that match, as many as given here (default 0)
    STUB_SSH_HANG_MATCH      a remote command that contains this text blocks before it runs, until
                             $STUB_DIR/release exists, except for the first
    STUB_SSH_HANG_SKIP       commands that match, as many as given here (default 0)
    STUB_SSH_TRUNCATE_UPLOAD number of bytes that a file written on the server keeps
    STUB_SSH_SUDO_PASSWORD   if set, sudo on the server asks for a password
    STUB_SSH_ECHO_STDIN      if set, the standard input is repeated on standard output,
    STUB_SSH_ECHO_STDIN_ERR  respectively on standard error
    STUB_SSH_STDOUT          replaces the standard output of the remote command,
    STUB_SSH_STDERR          respectively its standard error
    """
    env = os.environ
    options, words = parse(arguments, SSH_OPTION_STRING, 255, SSH_USAGE)
    if not words:
        raise Stop(255, "usage: %s\n" % SSH_USAGE)
    port, terminal = "22", False
    for name, value in options:
        if name == "-o":
            keyword, _, argument = value.replace("=", " ", 1).partition(" ")
            if keyword.lower() not in SSH_KEYWORDS:
                raise Stop(255, "command-line: line 0: Bad configuration option: %s\n" % keyword.lower())
            if not argument.strip():
                raise Stop(255, "command-line line 0: missing argument.\n")
        elif name == "-p":
            if not (value.isascii() and value.isdigit() and 0 < int(value) < 65536):
                raise Stop(255, "Bad port '%s'\n" % value)
            port = value
        elif name == "-e":
            if value != "none" and len(value) != 1 and not (len(value) == 2 and value[0] == "^"):
                raise Stop(255, "Bad escape character '%s'.\n" % value)
        elif name in ("-t", "-T"):
            terminal = name == "-t"
    destination, command = words[0], " ".join(words[1:])
    user, _, host = destination.rpartition("@")
    if not command:
        raise unmodelled("a login without a remote command")
    stdin = sys.stdin.buffer.read()
    call.record.update(stdin=stdin, destination=destination, command=command, terminal=terminal)

    def selected(kind):
        """True if the STUB_SSH_<kind>_* variables select this run."""
        text = env.get("STUB_SSH_%s_MATCH" % kind)
        if not text or text not in command:
            return False
        return call.count(kind.lower() + ".count") >= int(env.get("STUB_SSH_%s_SKIP" % kind, "0"))

    if selected("HANG"):
        call.hang()
    out = err = b""
    if selected("FAIL"):
        status = int(env.get("STUB_SSH_FAIL_RC", "1"))
    else:
        server = Server(call, user, terminal, stdin)
        status = server.shell(command)
        out, err = b"".join(server.out), b"".join(server.err)
    if status == 255:
        out, err = b"", ("ssh: connect to host %s port %s: Connection refused\n" % (host, port)).encode("utf-8")
    if "STUB_SSH_STDOUT" in env:
        out = os.fsencode(env["STUB_SSH_STDOUT"])
    if "STUB_SSH_STDERR" in env:
        err = os.fsencode(env["STUB_SSH_STDERR"])
    if stdin and env.get("STUB_SSH_ECHO_STDIN"):
        out += stdin + b"\n"
    if stdin and env.get("STUB_SSH_ECHO_STDIN_ERR"):
        err += stdin + b"\n"
    return status, out, err


AND = ["&&"]  # the two operators that shell_words returns between the words
TO = [">"]
PLAIN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-")


def shell_words(text):
    """Split a shell command line into words and the operators AND and TO.

    Quoting follows the shell: single quotes, double quotes and the
    backslash. Outside of them only the characters of PLAIN, blanks, "&&"
    and ">" are modelled: every other character can have a meaning for the
    shell. Returns None for a quotation that does not end. (The shlex
    module could do most of this but is slow to import.)
    """
    words, word, quote, position = [], None, None, 0
    while position < len(text):
        char = text[position]
        position += 1
        if quote == "'":
            if char == "'":
                quote = None
            else:
                word += char
        elif quote == '"':
            if char == '"':
                quote = None
            elif char == "\\" and text[position:position + 1] in ('"', "\\", "$", "`"):
                word += text[position]
                position += 1
            elif char in "$`":
                raise unmodelled("an expansion in '%s'" % text)
            else:
                word += char
        elif char in "'\"":
            quote, word = char, word or ""
        elif char == "\\" and position < len(text):
            word = (word or "") + text[position]
            position += 1
        elif char in PLAIN:
            word = (word or "") + char
        elif char in " \t\n>" or text[position - 1:position + 1] == "&&":
            if word is not None:
                words.append(word)
                word = None
            if char == ">":
                words.append(TO)
            elif char == "&":
                words.append(AND)
                position += 1
        else:
            raise unmodelled("the character '%s' in '%s'" % (char, text))
    if quote:
        return None
    return words if word is None else words + [word]


class Server:
    """The remote side of an ssh session: a shell and the few commands that kaltstart sends.

    The shell knows simple commands, "&&" between them and "> FILE" after
    one. The login user is root or becomes root through sudo; whatever
    touches a LUKS device or a file needs root. A session with a terminal
    stands for an operator who types what is asked for. The LUKS devices
    and the files of the server are kept below $STUB_DIR/server (see
    server_path).
    """

    def __init__(self, call, user, terminal, stdin):
        self.call = call
        self.root = user == "root"
        self.terminal = terminal
        self.stdin = stdin
        self.umask = 0o022
        self.out = []
        self.err = []

    def file(self, name):
        return server_path(self.call.directory, "files", name)

    def luks(self, device, slot=None):
        return server_path(self.call.directory, "luks", device, slot)

    def fail(self, status, message=None):
        """Print an error message and return the result of a failed command."""
        if message is not None:
            self.err.append(message.encode("utf-8", "surrogateescape") + b"\n")
        return status, b""

    def ask(self, prompt):
        """Show a prompt on the terminal, at once, followed by the line break of the answer.

        The run is on record before that: without a reader for the output
        of ssh it ends here, as the real ssh would.
        """
        self.call.log()
        sys.stdout.buffer.write(prompt + b"\n")
        sys.stdout.buffer.flush()

    def read_stdin(self, line=False):
        """Take the standard input of the session, or only its first line."""
        data, self.stdin = self.stdin, b""
        return data.split(b"\n")[0] if line else data

    def shell(self, text):
        """Run a command line and return its exit status."""
        words = shell_words(text)
        if words is None:
            return self.fail(2, "sh: 1: Syntax error: Unterminated quoted string")[0]
        status, command = 0, []
        for word in words + [AND]:
            if word is not AND:
                command.append(word)
            elif status == 0:
                status, command = self.simple_command(command), []
        return status

    def simple_command(self, words):
        """Run one command, with its standard output in a file of the server if "> FILE" follows it."""
        target = None
        if len(words) > 2 and words[-2] is TO:
            target, words = words[-1], words[:-2]
        if not words or TO in words:
            raise unmodelled("the shell syntax in '%s'" % self.call.record["command"])
        if target is None:
            status, out = self.run(words)
            self.out.append(out)
            return status
        if not self.root:
            return self.fail(2, "sh: 1: cannot create %s: Permission denied" % target)[0]
        status, out = self.run(words)
        if "STUB_SSH_TRUNCATE_UPLOAD" in os.environ:
            out = out[:int(os.environ["STUB_SSH_TRUNCATE_UPLOAD"])]
        os.makedirs(server_path(self.call.directory, "files"), exist_ok=True)
        with open(self.file(target), "wb") as handle:
            handle.write(out)
        os.chmod(self.file(target), 0o666 & ~self.umask)
        self.call.record.setdefault("wrote", []).append([target, 0o666 & ~self.umask])
        return status

    def run(self, words):
        """Run one command without redirection and return its exit status and its standard output."""
        commands = {"blkid": self.blkid, "cat": self.cat, "cryptroot-unlock": self.cryptroot_unlock,
                    "cryptsetup": self.cryptsetup, "rm": self.rm, "sh": self.sh, "sha256sum": self.sha256sum,
                    "sudo": self.sudo, "umask": self.set_umask}
        if words[0] not in commands:
            return self.fail(127, "sh: 1: %s: not found" % words[0])
        return commands[words[0]](words[1:])

    def sh(self, arguments):
        if len(arguments) != 2 or arguments[0] != "-c":
            raise unmodelled("sh without exactly -c COMMAND")
        return self.shell(arguments[1]), b""

    def sudo(self, arguments):
        """sudo [-n] COMMAND. With -n, and without a terminal, a password cannot be typed."""
        may_ask = arguments[:1] != ["-n"]
        command = arguments if may_ask else arguments[1:]
        if not command or command[0].startswith("-"):
            raise unmodelled("sudo with options other than -n")
        if os.environ.get("STUB_SSH_SUDO_PASSWORD") and not (may_ask and self.terminal):
            return self.fail(1, "sudo: a password is required")
        before, self.root = self.root, True
        try:
            return self.run(command)
        finally:
            self.root = before

    def set_umask(self, arguments):
        if len(arguments) != 1:
            raise unmodelled("umask without exactly one mode")
        self.umask = int(arguments[0], 8)
        return 0, b""

    def cat(self, arguments):
        if arguments:
            raise unmodelled("cat with arguments")
        return 0, self.read_stdin()

    def sha256sum(self, arguments):
        import hashlib
        if len(arguments) != 1 or arguments[0].startswith("-"):
            raise unmodelled("sha256sum without exactly one file")
        name = arguments[0]
        if not os.path.exists(self.file(name)):
            return self.fail(1, "sha256sum: %s: No such file or directory" % name)
        if not self.root:
            return self.fail(1, "sha256sum: %s: Permission denied" % name)
        with open(self.file(name), "rb") as handle:
            return 0, ("%s  %s\n" % (hashlib.sha256(handle.read()).hexdigest(), name)).encode("utf-8")

    def rm(self, arguments):
        force = arguments[:1] == ["-f"]
        names = arguments[1:] if force else arguments
        if not names or any(name.startswith("-") for name in names):
            raise unmodelled("rm with options other than -f")
        status = 0
        for name in names:
            if not os.path.exists(self.file(name)):
                if not force:
                    status = self.fail(1, "rm: cannot remove '%s': No such file or directory" % name)[0]
            elif not self.root:
                status = self.fail(1, "rm: cannot remove '%s': Permission denied" % name)[0]
            else:
                os.remove(self.file(name))
        return status, b""

    def blkid(self, arguments):
        if arguments != ["-t", "TYPE=crypto_LUKS", "-o", "device"]:
            raise unmodelled("blkid with other arguments than -t TYPE=crypto_LUKS -o device")
        devices = server_names(self.call.directory, "luks") if self.root else []
        return 0 if devices else 2, "".join(device + "\n" for device in devices).encode("utf-8", "surrogateescape")

    def slots(self, device):
        """The passphrases of a LUKS device by keyslot number."""
        found = {}
        for name in os.listdir(self.luks(device)):
            with open(self.luks(device, name), "rb") as handle:
                found[int(name)] = handle.read()
        return found

    def key(self, source, typed=None):
        """The passphrase that cryptsetup reads for --key-file or --new-keyfile; None if it cannot be read.

        "-" is the entire standard input. Without the option cryptsetup
        asks on the terminal, where the operator types TYPED, or else reads
        one line of the standard input.
        """
        if source == "-":
            return self.read_stdin()
        if source is not None:
            if not os.path.exists(self.file(source)):
                return None
            with open(self.file(source), "rb") as handle:
                return handle.read()
        return typed if self.terminal else self.read_stdin(line=True)

    def cryptsetup(self, arguments):
        """cryptsetup isLuks DEVICE, open --test-passphrase DEVICE and luksAddKey DEVICE."""
        flags = ("--test-passphrase", "--disable-external-tokens", "--verbose")
        valued = ("--key-file", "--new-keyfile")
        options, words = {}, []
        arguments = list(arguments)
        while arguments:
            word = arguments.pop(0)
            name, equals, value = word.partition("=")
            if word in flags:
                options[word] = True
            elif name in valued and (equals or arguments):
                options[name] = value if equals else arguments.pop(0)
            elif word.startswith("-") and word != "-":
                raise unmodelled("cryptsetup with the option %s" % word)
            else:
                words.append(word)
        if len(words) != 2 or words[0] not in ("isLuks", "open", "luksAddKey"):
            raise unmodelled("cryptsetup %s" % " ".join(words))
        action, device = words
        if action == "open" and "--test-passphrase" not in options:
            raise unmodelled("cryptsetup open without --test-passphrase")
        if action == "luksAddKey" and "--new-keyfile" not in options:
            raise unmodelled("cryptsetup luksAddKey without --new-keyfile")
        if not self.root:
            return self.fail(4, "Device %s does not exist or access denied." % device)
        if not os.path.isdir(self.luks(device)):
            return self.fail(1, None if action == "isLuks" else "Device %s is not a valid LUKS device." % device)
        if action == "isLuks":
            return 0, b""
        slots = self.slots(device)
        if action == "luksAddKey" and self.terminal and "--key-file" not in options:
            self.ask(b"Enter any existing passphrase: ")
        given = self.key(options.get("--key-file"), typed=slots.get(0) if action == "luksAddKey" else None)
        new = self.key(options["--new-keyfile"]) if action == "luksAddKey" else b""
        if given is None or new is None:
            return self.fail(1, "Failed to open key file.")
        opened = [number for number in sorted(slots) if slots[number] == given]
        if not opened:
            return self.fail(2, "No key available with this passphrase.")
        if action == "open":
            return 0, b"Key slot %d unlocked.\nCommand successful.\n" % opened[0] if "--verbose" in options else b""
        with open(self.luks(device, max(slots) + 1), "wb") as handle:
            handle.write(new)
        return 0, b""

    def cryptroot_unlock(self, arguments):
        """cryptroot-unlock in the initramfs, without a terminal.

        It prints the unlock prompt on standard output before it reads the
        passphrase, and everything else on standard error. Without a
        device that waits it prints no prompt and exits 0, or gives up
        with 1.
        """
        codes = os.environ.get("STUB_SSH_RCS", "0").split(",")
        status = int(codes[min(self.call.index, len(codes) - 1)])
        if status == 255 or status < 0:
            return status, b""
        if self.call.index < int(os.environ.get("STUB_SSH_PROMPTS", "1000")):
            self.read_stdin()
            self.err.append(b"cryptsetup: root_crypt set up successfully\n" if status == 0
                            else b"cryptsetup: cryptsetup failed, bad password or options?\n")
            return status, b"Please unlock disk root_crypt\n"
        if status != 0:
            self.err.append(b"Error: Timeout reached while waiting for askpass.\n")
        return status, b""


TOOLS = {"fido2-assert": run_fido2_assert, "fido2-cred": run_fido2_cred, "fido2-token": run_fido2_token,
         "ssh": run_ssh, "ssh-keygen": run_ssh_keygen}


def main():
    # A write to a pipe without a reader ends the real programs. Python
    # would raise an exception instead.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    call = Call(sys.argv[1], sys.argv[2:])
    try:
        status, out, err = TOOLS[call.name](call, call.record["argv"])
    except Stop as stop:
        status, out, err = stop.args[0], b"", stop.args[1].encode("utf-8", "surrogateescape")
        if status == UNMODELLED:
            call.problem(stop.args[1])
    except Exception:
        import traceback
        call.problem(traceback.format_exc())
        status, out, err = UNMODELLED, b"", b"stub: internal error\n"
    call.finish(status, out, err)


if __name__ == "__main__":
    main()
