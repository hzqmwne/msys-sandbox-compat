param(
    [ValidateSet('Release','RelWithDebInfo')][string]$Configuration='RelWithDebInfo',
    [switch]$Install
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'tools\msvc-env.ps1')
& $cmake -S $PSScriptRoot -B (Join-Path $PSScriptRoot 'build') -G 'NMake Makefiles' "-DCMAKE_BUILD_TYPE=$Configuration"
if ($LASTEXITCODE) { throw 'CMake configure failed' }
& $cmake --build (Join-Path $PSScriptRoot 'build')
if ($LASTEXITCODE) { throw 'C++ build failed' }
if ($Install) {
    & $cmake --install (Join-Path $PSScriptRoot 'build') --prefix (Join-Path $PSScriptRoot 'unused\package')
    if ($LASTEXITCODE) { throw 'Package installation failed' }
}
