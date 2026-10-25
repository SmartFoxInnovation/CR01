[CmdletBinding()]
param(
    [string]$ToolchainRoot = 'C:\msys64\ucrt64',
    [string]$OpenSSLRoot = $env:OPENSSL_ROOT,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
if ($Help) {
    Write-Output 'Build CR01-SC for Windows with MSYS2 UCRT64 GCC and patched OpenSSL; see docs/GUIDE.md.'
    Write-Output 'Usage: powershell -File tools/build_native.ps1 [-ToolchainRoot C:\msys64\ucrt64] [-OpenSSLRoot PREFIX]'
    exit 0
}
if ($env:OS -ne 'Windows_NT') { throw 'Use bash tools/build_native.sh on Linux' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolchain = (Resolve-Path -LiteralPath $ToolchainRoot).Path
$compiler = Join-Path $toolchain 'bin\g++.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'MSYS2 UCRT64 GCC is required' }
if (-not $OpenSSLRoot) { $OpenSSLRoot = $toolchain }
$openssl = (Resolve-Path -LiteralPath $OpenSSLRoot).Path
$runtimeNames = @('libcrypto-3-x64.dll','libgcc_s_seh-1.dll','libstdc++-6.dll','libwinpthread-1.dll')
foreach ($name in $runtimeNames) {
    $runtimeRoot = if ($name -eq 'libcrypto-3-x64.dll') { $openssl } else { $toolchain }
    if (-not (Test-Path -LiteralPath (Join-Path $runtimeRoot ('bin\' + $name)) -PathType Leaf)) {
        throw "Required runtime missing: $name"
    }
}
$nativeBuild = Join-Path $projectRoot 'bin'
if (Test-Path -LiteralPath $nativeBuild) {
    $item = Get-Item -LiteralPath $nativeBuild
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'bin must be a real directory, not a link'
    }
} else { New-Item -ItemType Directory -Path $nativeBuild | Out-Null }
foreach ($name in @('cr01sc.exe') + $runtimeNames) {
    $target = Join-Path $nativeBuild $name
    if (Test-Path -LiteralPath $target) {
        $item = Get-Item -LiteralPath $target
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Build target must be a regular file: $name"
        }
    }
}
$scratchParent = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).Path.TrimEnd([char[]]'\/')
$scratch = Join-Path $scratchParent ('cr01-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$savedPath = $env:PATH
try {
    $env:PATH = (Join-Path $openssl 'bin') + ';' + (Join-Path $toolchain 'bin') + ';' + $savedPath
    $flags = @('-std=c++20','-O3','-DNDEBUG','-Wall','-Wextra','-Wpedantic','-Werror',
               '-I',(Join-Path $openssl 'include'))
    $libraries = @('-L',(Join-Path $openssl 'lib'),'-lcrypto')
    $probe = Join-Path $scratch 'check-openssl.exe'
    & $compiler @flags (Join-Path $projectRoot 'tools\check_openssl.cpp') @libraries -o $probe
    if ($LASTEXITCODE -ne 0) { throw 'Patched OpenSSL development files are required; see docs/GUIDE.md' }
    & $probe
    if ($LASTEXITCODE -ne 0) { throw 'Required OpenSSL algorithms are unavailable; see docs/GUIDE.md' }
    $built = Join-Path $scratch 'cr01sc.exe'
    & $compiler @flags (Join-Path $projectRoot 'src\cpp\main.cpp') @libraries -o $built
    if ($LASTEXITCODE -ne 0) { throw 'CR01-SC native build failed' }
    & $built --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Built engine did not start' }
    foreach ($name in $runtimeNames) {
        $runtimeRoot = if ($name -eq 'libcrypto-3-x64.dll') { $openssl } else { $toolchain }
        Copy-Item -LiteralPath (Join-Path $runtimeRoot ('bin\' + $name)) -Destination (Join-Path $nativeBuild $name)
    }
    Move-Item -LiteralPath $built -Destination (Join-Path $nativeBuild 'cr01sc.exe') -Force
    Write-Output (Join-Path $nativeBuild 'cr01sc.exe')
} finally {
    $env:PATH = $savedPath
    # Only these two generated files may be removed; never recurse into a temp path.
    if ((Split-Path -Parent $scratch) -ne $scratchParent -or
        ((Get-Item -LiteralPath $scratch).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Refusing unexpected build scratch directory'
    }
    foreach ($name in @('check-openssl.exe','cr01sc.exe')) {
        $target = Join-Path $scratch $name
        if (Test-Path -LiteralPath $target) {
            $item = Get-Item -LiteralPath $target
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Refusing unexpected build scratch entry'
            }
            Remove-Item -LiteralPath $target
        }
    }
    Remove-Item -LiteralPath $scratch
}
