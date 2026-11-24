#requires -Version 5.0
param(
    [ValidateSet('Release','RelWithDebInfo')][string]$Configuration='RelWithDebInfo',
    [switch]$Install,
    [switch]$Tests,
    [switch]$Tools
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'tools\msvc-env.ps1')
$buildDirectory = Join-Path $PSScriptRoot 'build'
$configureArgs = @(
    '-S', $PSScriptRoot, '-B', $buildDirectory, '-G', 'NMake Makefiles'
    "-DCMAKE_BUILD_TYPE=$Configuration"
    "-DBUILD_TESTING=$([int]$Tests.IsPresent)"
    "-DMSYS_SANDBOX_COMPAT_BUILD_TOOLS=$([int]$Tools.IsPresent)"
)
& $cmake @configureArgs
if ($LASTEXITCODE) { throw 'CMake configure failed' }
& $cmake --build $buildDirectory
if ($LASTEXITCODE) { throw 'C++ build failed' }
# Retire the former agent filename after rebuilding successfully.
$oldAgent = Join-Path $buildDirectory 'bin/msys-sandbox-compat.dll'
if (Test-Path -LiteralPath $oldAgent -PathType Leaf) {
    Remove-Item -LiteralPath $oldAgent
}
if ($Install) {
    $package = Join-Path $buildDirectory 'package'
    & $cmake --install $buildDirectory --prefix $package
    if ($LASTEXITCODE) { throw 'Package installation failed' }
    # Retire files left by earlier installs into this staging directory.
    $obsoleteNames = @('msys-sandbox-compat.exe','msys-sandbox-compat.dll')
    if (!$Tools) { $obsoleteNames += 'psec-run.exe' }
    foreach ($name in $obsoleteNames) {
        $obsolete = Join-Path (Join-Path $package 'bin') $name
        if (Test-Path -LiteralPath $obsolete -PathType Leaf) {
            Remove-Item -LiteralPath $obsolete
        }
    }
}
