#!/usr/bin/env bash
set -euo pipefail

if [[ $# == 1 && ( $1 == --help || $1 == -h ) ]]; then
    printf '%s\n' 'Build CR01-SC for Linux with a C++20 compiler and patched OpenSSL; see docs/GUIDE.md.' \
        'Usage: bash tools/build_native.sh' \
        'Optional: CXX=/path/to/g++ OPENSSL_ROOT=/path/to/openssl bash tools/build_native.sh'
    exit 0
fi
if [[ $# != 0 ]]; then printf '%s\n' 'Unknown argument; use --help' >&2; exit 2; fi
if [[ $(uname -s) != Linux ]]; then
    printf '%s\n' 'Linux required; use tools/build_native.ps1 on Windows' >&2
    exit 1
fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
compiler=${CXX:-g++}
if ! command -v -- "$compiler" >/dev/null 2>&1; then
    printf '%s\n' 'C++20 compiler missing; install g++ or set CXX to a compiler executable' >&2
    exit 1
fi
flags=(-std=c++20 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -Werror)
libraries=()
if [[ -n ${OPENSSL_ROOT:-} ]]; then
    prefix=$(cd -- "$OPENSSL_ROOT" && pwd -P)
    if [[ ! -d $prefix/include/openssl ]]; then
        printf '%s\n' 'OPENSSL_ROOT must contain include/openssl and lib or lib64' >&2; exit 1
    fi
    libdir=
    for candidate in "$prefix/lib64" "$prefix/lib"; do
        if [[ -f $candidate/libcrypto.so || -f $candidate/libcrypto.a ]]; then libdir=$candidate; break; fi
    done
    if [[ -z $libdir ]]; then printf '%s\n' 'OPENSSL_ROOT has no libcrypto development library' >&2; exit 1; fi
    flags+=(-I "$prefix/include")
    libraries+=(-L "$libdir" -Xlinker -rpath -Xlinker "$libdir")
fi
libraries+=(-lcrypto)
if [[ -L $root/bin || ( -e $root/bin && ! -d $root/bin ) || -L $root/bin/cr01sc ||
      ( -e $root/bin/cr01sc && ! -f $root/bin/cr01sc ) ]]; then
    printf '%s\n' 'bin and its engine target must not be links or unexpected file types' >&2; exit 1
fi
temp_parent=$(cd -- "${TMPDIR:-/tmp}" && pwd -P)
scratch=$(mktemp -d "$temp_parent/cr01-build.XXXXXXXX")
[[ -n $scratch && -d $scratch && ! -L $scratch ]] || exit 1
cleanup() {
    if [[ -z $scratch || ${scratch%/*} != "$temp_parent" || ! -d $scratch || -L $scratch ]]; then
        printf '%s\n' 'Refusing unexpected build scratch directory' >&2; return 1
    fi
    for name in check-openssl cr01sc; do
        target=$scratch/$name
        if [[ -L $target || ( -e $target && ! -f $target ) ]]; then
            printf '%s\n' 'Refusing unexpected build scratch entry' >&2; return 1
        fi
        rm -f -- "$target"
    done
    rmdir -- "$scratch"
}
trap cleanup EXIT
if ! "$compiler" "${flags[@]}" "$root/tools/check_openssl.cpp" "${libraries[@]}" -o "$scratch/check-openssl"; then
    printf '%s\n' 'Patched OpenSSL development headers/libraries are required; see docs/GUIDE.md' >&2; exit 1
fi
if ! "$scratch/check-openssl"; then
    printf '%s\n' 'Required OpenSSL algorithms are unavailable; see docs/GUIDE.md' >&2; exit 1
fi
"$compiler" "${flags[@]}" "$root/src/cpp/main.cpp" "${libraries[@]}" -o "$scratch/cr01sc"
"$scratch/cr01sc" --help >/dev/null
mkdir -p -- "$root/bin"
mv -f -- "$scratch/cr01sc" "$root/bin/cr01sc"
printf '%s\n' "$root/bin/cr01sc"
