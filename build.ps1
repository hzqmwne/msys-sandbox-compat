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
    & $cmake --install $buildDirectory --prefix (Join-Path $buildDirectory 'package')
    if ($LASTEXITCODE) { throw 'Package installation failed' }
}
