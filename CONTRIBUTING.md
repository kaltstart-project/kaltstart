# Contributing

Reports are welcome through the issue tracker of the repository. Security
issues are reported privately, as described in [SECURITY.md](SECURITY.md).
A report must not contain passphrases, PINs, private keys, the output of
`kaltstart derive`, or a credential ID together with its salt.

Results of the checks in [docs/verification.md](docs/verification.md) with
a physical token are particularly welcome. Such a report names the token
model and firmware version, the output of `fido2-token -I DEVICE`, the
version of fido2-tools, the operating system, and the result of every check
that was carried out.

A change keeps the program a single file that uses the Python standard
library only, covers new behavior with tests, and passes the test suite:

```sh
python3 -I -m unittest discover -s tests
```
