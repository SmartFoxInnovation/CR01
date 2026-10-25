# Third-party notices

CR01-SC uses the licence in [LICENSE](LICENSE). Dependencies retain their own
licences; the CR01 noncommercial restriction does not replace those terms.
No third-party packages or binaries are bundled in this source archive.

## Checked dependencies

The supplied locks record these versions. Verify the exact installed packages
when rebuilding; this summary is not a substitute for their upstream notices.

| Python package | Version | Licence expression |
| --- | --- | --- |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| cffi | 2.1.1 | MIT-0 |
| pycparser | 3.12 | BSD-3-Clause |

| MSYS2 UCRT64 package | Version |
| --- | --- |
| mingw-w64-ucrt-x86_64-openssl | 3.6.5-1 |
| mingw-w64-ucrt-x86_64-gcc | 15.2.0-13 |
| mingw-w64-ucrt-x86_64-gcc-libs | 15.2.0-13 |
| mingw-w64-ucrt-x86_64-libwinpthread | 13.0.0.r560.g3197fc7d6-1 |

OpenSSL provides the native cryptographic backend. GCC and its runtime packages
are separate upstream components, not CR01 source. See
[requirements.lock](requirements.lock) and the
[native lock](config/native-packages.lock) for the recorded package set.
The JSON native lock includes the extracted OpenSSL package source/checksum and
portable licence-file paths. Other native packages were read from the existing
MSYS2 package database. An unidentifiable custom prefix is reported as incomplete,
not substituted with the shared installation's version.

Upstream references: [cryptography changelog](https://cryptography.io/en/latest/changelog/),
[OpenSSL 3.6 release notes](https://openssl-library.org/news/openssl-3.6-notes/) and
[MSYS2 OpenSSL package](https://packages.msys2.org/packages/mingw-w64-ucrt-x86_64-openssl).

## Collect exact local notices

```powershell
python tools/dependencies.py --out validation-output/third-party
```

The generated JSON and Markdown identify installed packages and hash their
licence files. They stay outside the small source ZIP. If redistributing
dependencies, wheels, containers, installers or standalone binaries, include
the upstream licence texts and notices for the exact versions distributed.
Preserve an upstream NOTICE where its terms require it.

## Test vectors

Original CR01 vectors use synthetic, deliberately public test values and remain
under the repository licence. Public primitive known-answer sources are named
in the check implementation.
