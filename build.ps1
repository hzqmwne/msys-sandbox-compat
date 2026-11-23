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
if ($Install) {
    $package = Join-Path $buildDirectory 'package'
    & $cmake --install $buildDirectory --prefix $package
    if ($LASTEXITCODE) { throw 'Package installation failed' }
    # Retire the development pair left by older installs into this staging directory.
    foreach ($name in @('msys-sandbox-compat.exe','msys-sandbox-compat.dll')) {
        $obsolete = Join-Path (Join-Path $package 'bin') $name
        if (Test-Path -LiteralPath $obsolete -PathType Leaf) {
            Remove-Item -LiteralPath $obsolete
        }
    }
}
