param([string]$GitRoot='C:\Program Files\Git',[string]$EvidenceDirectory='',
      [string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'),
      [ValidateSet('Psec','WriteRestricted','FullRestricted')][string]$Environment='Psec',
      [switch]$NativeRelay,
      [ValidateRange(1,1000)][int]$ThreadRepetitions=1)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root = Split-Path $PSScriptRoot -Parent
$restricted = $Environment -ne 'Psec'
$suite = if ($restricted) { 'restricted-' + $Environment.ToLowerInvariant() } else { 'process-chain' }
if ($NativeRelay) { $suite = 'relay-' + $suite }
$state = Join-Path $root ('unused\runtime\' + $suite)
$evidence = if ($EvidenceDirectory) { [IO.Path]::GetFullPath($EvidenceDirectory) }
            else { Join-Path $root ('unused\evidence\current\' + $suite) }
New-Item -ItemType Directory -Force $state,$evidence,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$sourceBinaries = $BinaryDirectory
$fixtureBinaries = Get-TestFixtureDirectory $sourceBinaries
if ($restricted) {
    $BinaryDirectory = Initialize-RestrictedTestFiles $sourceBinaries $state
}
$policy = Join-Path $state 'policy.json'
$canary = if ($restricted) { Join-Path $state 'denied.txt' } else { Join-Path $PSScriptRoot 'fixtures\denied.txt' }
if (!$restricted) {
    Write-TestJson $policy @{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot,$root);readwritePaths=@($state);deniedPaths=@($canary)}}
}
$launcher = if ($restricted) { Join-Path $fixtureBinaries 'restricted-run.exe' }
            else { Get-PsecLauncher $BinaryDirectory }
$compat = Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'
$bridge = Join-Path $(if ($restricted) {$BinaryDirectory} else {$fixtureBinaries}) 'native-bridge.exe'
$bash = Join-Path $GitRoot 'usr\bin\bash.exe'
$runtime = Join-Path $GitRoot 'usr\bin\msys-2.0.dll'
[string[]]$prefix = if ($restricted) {
    @($(if ($Environment -eq 'WriteRestricted') {'write'} else {'full'}),$state)
} else { @($policy) }
function Shell-Command([object[]]$Arguments) {
    return (($Arguments | ForEach-Object { "'" + ([string]$_).Replace("'","'\''") + "'" }) -join ' ')
}
$fork = (Join-Path $(if ($restricted) {$BinaryDirectory} else {(Join-Path $PSScriptRoot 'fixtures')}) 'fork.pl').Replace('\','/')
$deny = $canary.Replace('\','/')
# Old output can carry a protected ACL tied to a different logon session.
$writeName = 'chain-write-' + [Guid]::NewGuid().ToString('N') + '.txt'
$writePath = Join-Path $state $writeName
$payload = "set -eu; export PATH=/usr/bin:/bin; perl '$fork' $ThreadRepetitions; " +
    'test "$(printf fork-command)" = fork-command; test "$(printf ''b\na\n'' | sort | head -1)" = a; ' +
    "if cat '$deny'; then exit 81; fi; if printf forbidden > '$deny'; then exit 82; fi; " +
    ('printf permitted > {0}; test "$(cat {0})" = permitted; echo CHAIN-WORKLOAD-PASS; exit 37' -f $writeName)
if ($restricted) {
    $check = Shell-Command @((Join-Path $BinaryDirectory 'restricted-run.exe').Replace('\','/'),
        'probe',$state.Replace('\','/'))
    $payload = 'set -e; ' + $check + '; ' + $payload
}
$results = [Collections.Generic.List[object]]::new()
$ordinary = $null
try {
    if ($restricted) {
        # Record the same-token unmodified baseline; its failure is not an acceptance result.
        $rawInfo = New-TestProcessInfo $launcher ($prefix + @($bash,'--noprofile','--norc','-c',
            'set -euo pipefail; test "$(printf raw-fork | cat)" = raw-fork; echo RAW-WORKLOAD-PASS')) $state
        $raw = Invoke-TestProcess $rawInfo 30000
        Save-TestOutput $raw $evidence 'raw-baseline'
        Write-TestJson (Join-Path $evidence 'raw-baseline.json') @{
            ExitCode=$raw.ExitCode;WorkloadCompleted=$raw.Output.Contains('RAW-WORKLOAD-PASS')
        }
        # An ordinary MSYS session holds its global objects throughout both restricted chains.
        $ordinaryInfo = New-TestProcessInfo $bash @('--noprofile','--norc','-c',
            'echo ORDINARY-MSYS-READY; read -r done') $state
        $ordinaryInfo.RedirectStandardInput = $true
        $ordinary = [Diagnostics.Process]::Start($ordinaryInfo)
        $ordinaryError = $ordinary.StandardError.ReadToEndAsync()
        $ready = $ordinary.StandardOutput.ReadLineAsync()
        if (!$ready.Wait(10000) -or $ready.GetAwaiter().GetResult() -ne 'ORDINARY-MSYS-READY') {
            throw 'Ordinary MSYS coexistence fixture did not start'
        }
    }
    $cases=@(@{Depth=0;Root='native';Explicit=$false},@{Depth=2;Root='native';Explicit=$false})
    if ($NativeRelay) {
        $cases+=@(@{Depth=2;Root='msys';Explicit=$false},@{Depth=0;Root='native';Explicit=$true})
        $cases+=@(@{Depth=2;Root='native';Explicit=$false;Suspended=$true})
    }
    foreach ($case in $cases) {
        $depth=$case.Depth
        $nativeArgs=@($bridge.Replace('\','/'))
        if ($NativeRelay) {$nativeArgs+='--relay'}
        if ($case.Suspended) {$nativeArgs+='--suspended'}
        $nativeArgs+=@($depth)
        if (!$NativeRelay -or $case.Explicit) {
            $nativeArgs+=@($compat.Replace('\','/'))
            if ($NativeRelay) {$nativeArgs+='--trace'}
            else {$nativeArgs+='--no-native-relay'}
            $nativeArgs+=@('--runtime',$runtime.Replace('\','/'))
        }
        $inner = Shell-Command ($nativeArgs+@($bash.Replace('\','/'),'--noprofile','--norc','-c',$payload))
        $outer = 'export MSYS2_ARG_CONV_EXCL="*"; ' + $inner
        # The first native bridge records the original runner ACL, before MSYS has run.
        $expectedBridges=$depth+2
        $arguments = if ($NativeRelay) {
            $target=@($compat,'--native-relay','--runtime',$runtime)
            if ($case.Root -eq 'native') {$target+=@($bridge,'--relay',0)}
            else {$expectedBridges--}
            $prefix+$target+@($bash,'--noprofile','--norc','-c',$outer)
        } else {
            $prefix+@($bridge,0,$compat,'--no-native-relay','--runtime',$runtime,$bash,
                '--noprofile','--norc','-c',$outer)
        }
        $info = New-TestProcessInfo $launcher $arguments $state
        $result = Invoke-TestProcess $info 60000
        $name = "native-depth-$($depth+1)"
        if ($NativeRelay) {$name="$($case.Root)-depth-$($depth+1)-explicit-$($case.Explicit)"}
        if ($case.Suspended) {$name+='-suspended'}
        Save-TestOutput $result $evidence $name
        $acls = @([regex]::Matches($result.Error,'\[bridge\] clean=1 depth=\d+ default=([^\r\n]+)') |
            ForEach-Object { $_.Groups[1].Value })
        # A native entry records the runner policy before MSYS explicitly sets
        # its own ACL. Descendants retain that adapted request, not the runner snapshot.
        $descendantAcls = if ($case.Root -eq 'native') { @($acls | Select-Object -Skip 1) } else { $acls }
        $passed = $result.ExitCode -eq 37 -and $result.Output.Contains('CHAIN-WORKLOAD-PASS') -and
            $result.Output.Contains('fork from a secondary POSIX thread works') -and $result.Output -notmatch '(?m)^not ok' -and
            $acls.Count -eq $expectedBridges -and $descendantAcls.Count -gt 0 -and
            @($descendantAcls | Select-Object -Unique).Count -eq 1 -and
            $result.Error -notmatch 'fatal error|fork: retry|child_copy:|\[fatal\]'
        if ($restricted) { $passed = $passed -and $result.Output.Contains('RESTRICTED-TOKEN-AND-ACL-PASS') }
        if ($NativeRelay) {
            $passed=$passed -and [regex]::Matches($result.Error,'\[bridge-mode\] relay=1 hooks=1').Count -eq $expectedBridges
        }
        if ($case.Suspended) {
            $passed=$passed -and [regex]::Matches($result.Error,'suspended-preserved=1').Count -eq ($depth+1)
        }
        $results.Add([pscustomobject]@{Name=$name;Passed=$passed;ExitCode=$result.ExitCode;NativeBridges=$acls.Count})
        Write-Output "$name pass=$passed exit=$($result.ExitCode) bridges=$($acls.Count)"
    }
    if ($NativeRelay) {
        $arguments=$prefix+@($compat,'--trace','--native-relay','--runtime',$runtime,$bridge,'--relay',
            '--change-default',1,$bash,'--noprofile','--norc','-c','echo RELAY-DEFAULT-DACL-PASS; exit 37')
        $result=Invoke-TestProcess (New-TestProcessInfo $launcher $arguments $state) 30000
        Save-TestOutput $result $evidence 'changed-default-dacl'
        $original=[regex]::Match($result.Error,'\[bridge\] clean=1 depth=1 default=([^\r\n]+)')
        $changed=[regex]::Match($result.Error,'\[bridge\] changed-default=([^\r\n]+)')
        $inherited=[regex]::Match($result.Error,'\[bridge\] clean=1 depth=0 default=([^\r\n]+)')
        $passed=$result.ExitCode -eq 37 -and $result.Output.Contains('RELAY-DEFAULT-DACL-PASS') -and
            $original.Success -and $changed.Success -and $inherited.Success -and
            $original.Groups[1].Value -cne $changed.Groups[1].Value -and
            $changed.Groups[1].Value -ceq $inherited.Groups[1].Value -and
            $result.Error.Contains('[bridge] changed created=1 error=0 restored=1')
        $results.Add([pscustomobject]@{Name='changed-default-dacl';Passed=$passed;ExitCode=$result.ExitCode;NativeBridges=2})
        Write-Output "changed-default-dacl pass=$passed exit=$($result.ExitCode)"
    }
    if ($restricted -and $ordinary.HasExited) { throw 'Ordinary MSYS exited during the restricted workload' }
    Write-TestJson (Join-Path $evidence 'results.json') $results
    if (@($results | Where-Object {!$_.Passed}).Count) { throw 'Real MSYS process-chain workload failed' }
    Write-Output 'PROCESS-CHAIN-ALL-PASS'
} finally {
    if ($null -ne $ordinary) {
        if (!$ordinary.HasExited) {
            $ordinary.StandardInput.Close()
            if (!$ordinary.WaitForExit(3000)) { Stop-TestProcess $ordinary; $ordinary.WaitForExit() }
        }
        [IO.File]::WriteAllText((Join-Path $evidence 'ordinary.stderr.txt'),$ordinaryError.GetAwaiter().GetResult())
        $ordinary.Dispose()
    }
    Remove-Item -LiteralPath $writePath -ErrorAction SilentlyContinue
}
