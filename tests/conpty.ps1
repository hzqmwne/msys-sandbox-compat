param([string]$GitRoot='C:\Program Files\Git',[string]$EvidenceDirectory='',
      [string]$BinaryDirectory=(Join-Path (Split-Path $PSScriptRoot -Parent) 'build\bin'),
      [ValidateSet('Psec','WriteRestricted','FullRestricted','Existing')][string]$Environment='Psec',
      [switch]$NativeRelay,
      [ValidateRange(1,1000)][int]$ThreadRepetitions=1)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$root=Split-Path $PSScriptRoot -Parent
$restricted=$Environment -in @('WriteRestricted','FullRestricted')
$existing=$Environment -eq 'Existing'
$suite=if($restricted -or $existing){'conpty-'+$Environment.ToLowerInvariant()}else{'conpty'}
if($NativeRelay){$suite='relay-'+$suite}
$state=Join-Path $root $(if($restricted -or $existing){'unused\runtime\'+$suite}else{'unused\runtime'})
$report=Join-Path $root ('unused\evidence\current\'+$suite)
if($EvidenceDirectory){$report=[IO.Path]::GetFullPath($EvidenceDirectory)}
New-Item -ItemType Directory -Force $report,$state,(Join-Path $state 'tmp'),(Join-Path $state 'home') | Out-Null
$policy=Join-Path $state 'conpty-policy.json'
if(!$restricted -and !$existing){
    @{filesystem=@{readonlyPaths=@($env:SystemRoot,$GitRoot);readwritePaths=@($root);deniedPaths=@((Join-Path $PSScriptRoot 'fixtures\denied.txt'))}} | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8NoBOM -LiteralPath $policy
}
$sourceBinaries=$BinaryDirectory
$fixtureBinaries=Get-TestFixtureDirectory $sourceBinaries
if($restricted){$BinaryDirectory=Initialize-RestrictedTestFiles $sourceBinaries $state}
Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
public sealed class TerminalTest : IDisposable {
    public Process P;
    public readonly StringBuilder Output = new StringBuilder();
    public readonly StringBuilder Error = new StringBuilder();
    Task outputTask, errorTask;
    public TerminalTest(ProcessStartInfo info) {
        P=Process.Start(info);
        outputTask=Drain(P.StandardOutput, Output); errorTask=Drain(P.StandardError, Error);
    }
    static async Task Drain(System.IO.StreamReader stream, StringBuilder result) {
        var buffer=new char[2048]; int count;
        while((count=await stream.ReadAsync(buffer,0,buffer.Length))>0) lock(result) result.Append(buffer,0,count);
    }
    public void Send(string input) {P.StandardInput.Write(input);P.StandardInput.Flush();}
    public string Text { get {lock(Output) return Output.ToString();} }
    public void Await(string marker) {
        AwaitFrom(marker, 0);
    }
    public void AwaitFrom(string marker, int position) {
        var deadline=DateTime.UtcNow.AddSeconds(30);
        while(DateTime.UtcNow<deadline) {
            if(Text.IndexOf(marker, position, StringComparison.Ordinal)>=0) return;
            if(P.HasExited) throw new Exception("Exited waiting for " + marker + ": " + Text);
            Thread.Sleep(20);
        }
        throw new Exception("Timeout waiting for " + marker + ": " + Text);
    }
    public int Finish() {
        if(!P.WaitForExit(30000)) throw new Exception("ConPTY exit timeout");
        Task.WaitAll(outputTask,errorTask); return P.ExitCode;
    }
    public void Dispose() {if(!P.HasExited) P.Kill(true); P.Dispose();}
}
"@
[string[]]$prefix=if($existing){@()}elseif($restricted){@($(if($Environment -eq 'WriteRestricted'){'write'}else{'full'}),$state)}else{@($policy)}
$targetArguments=@('--runtime',(Join-Path $GitRoot 'usr\bin\msys-2.0.dll'),'--conpty','--conpty-size','120x40',(Join-Path $GitRoot 'usr\bin\bash.exe'),'--noprofile','--norc','-i')
if(!$NativeRelay){$targetArguments=@('--no-native-relay')+$targetArguments}
$arguments=if($existing){$targetArguments}else{$prefix+@((Join-Path $BinaryDirectory 'msys-sandbox-compat.exe'))+$targetArguments}
$launcher=if($existing){Join-Path $sourceBinaries 'msys-sandbox-compat.exe'}elseif($restricted){Join-Path $fixtureBinaries 'restricted-run.exe'}else{Get-PsecLauncher $sourceBinaries}
$info=New-TestProcessInfo $launcher $arguments $state
$info.RedirectStandardInput=$true
$info.StandardInputEncoding=[Text.UTF8Encoding]::new($false)
$info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
$t=[TerminalTest]::new($info)
$passed=$false
$exitCode=$null
$terminalWritePath=$null
try {
    $t.Send("export PS1='MSYS-SANDBOX-COMPAT> '; export PATH=/usr/bin:/bin; /usr/bin/stty -echo; printf '\nREADY-INPUT\n'`r")
    $t.Await("READY-INPUT`r`n")
    $t.Send('export LC_ALL=C.UTF-8; printf "CONPTY-UNICODE-%s\n" "中文-é-Ａ"'+"`r")
    $t.Await("CONPTY-UNICODE-中文-é-Ａ`r`n")
    if($restricted -or $existing){
        $fork=(Join-Path $(if($restricted){$BinaryDirectory}else{(Join-Path $PSScriptRoot 'fixtures')}) 'fork.pl').Replace('\','/').Replace("'","'\''")
        $workload=''
        if($restricted){
            $probe=(Join-Path $BinaryDirectory 'restricted-run.exe').Replace('\','/').Replace("'","'\''")
            $workspace=$state.Replace('\','/').Replace("'","'\''")
            $workload="'$probe' probe '$workspace' || exit 87; "
        }
        # A previous login's restricted token may have created a protected DACL.
        $terminalWriteName='terminal-write-'+[Guid]::NewGuid().ToString('N')+'.txt'
        $terminalWritePath=Join-Path $state $terminalWriteName
        $workload+="perl '$fork' $ThreadRepetitions || exit 88; " +
            ('printf permitted > {0} && test "$(cat {0})" = permitted || exit 89; echo TERMINAL-POLICY-PASS' -f $terminalWriteName)
        $t.Send($workload+"`r")
        $t.Await("TERMINAL-POLICY-PASS`r`n")
    }
    $t.Send('test -t 0 && test -t 1 && test -t 2 || exit 81; test "$(stty size)" = "40 120" || exit 82; test "$(printf redirected)" = redirected || exit 83; (echo CONPTY-FORK-PASS); MSYS2_ARG_CONV_EXCL="*" /c/Windows/System32/cmd.exe /d /c "echo CONPTY-NATIVE-PASS"; echo CONTROL-READY; sleep 30'+"`r")
    $t.Await("CONTROL-READY`r`n")
    [Threading.Thread]::Sleep(200); $position=$t.Text.Length; $t.Send([string][char]3)
    $t.AwaitFrom('MSYS-SANDBOX-COMPAT> ',$position)
    $t.Send('s=$?; test "$s" = 130 || exit 84; echo CTRL-C-PASS; test -o monitor || exit 86; sleep 30 & p=$!; sleep 0.2; kill -STOP "$p"; sleep 0.2; jobs -s; echo STOP-READY'+"`r")
    $t.Await("STOP-READY`r`n")
    if($t.Text -notmatch 'Stopped'){throw 'Background job did not stop'}
    $t.Send('bg %1; echo BACKGROUND-READY; fg %1'+"`r")
    $t.Await("BACKGROUND-READY`r`n")
    [Threading.Thread]::Sleep(200); $position=$t.Text.Length; $t.Send([string][char]3)
    $t.AwaitFrom('MSYS-SANDBOX-COMPAT> ',$position)
    $finish='s=$?; test "$s" = 130 || exit 85; echo JOB-CONTROL-PASS; '
    if($restricted){$finish+="'$probe' probe '$workspace' || exit 90; "}
    $t.Send($finish+'exit 37'+"`r")
    $exitCode=$t.Finish()
    if($exitCode -ne 37){throw "Unexpected terminal exit $exitCode"}
    foreach($marker in @('CONPTY-FORK-PASS','CONPTY-NATIVE-PASS','CTRL-C-PASS','JOB-CONTROL-PASS')) {
        if(!$t.Text.Contains($marker)){throw "Missing $marker"}
    }
    if($t.Text -match 'no job control|cannot set terminal process group'){throw 'Job control diagnostics'}
    if(($t.Text+$t.Error.ToString()) -match 'fatal error|fork: retry|child_copy:|\[fatal\]'){
        throw 'Terminal runtime diagnostics'
    }
    if($restricted -and [regex]::Matches($t.Text,'RESTRICTED-TOKEN-AND-ACL-PASS').Count -ne 2){
        throw 'Restricted terminal policy probes failed'
    }
    if(($restricted -or $existing) -and
        (!$t.Text.Contains('fork from a secondary POSIX thread works') -or $t.Text -match 'not ok \d')){
        throw 'Terminal Perl workload failed'
    }
    $passed=$true
    Write-Output 'CONPTY-ALL-PASS: tty, size, UTF-8, redirection, fork, native child, Ctrl+C, stop/bg/fg, exit=37'
} finally {
    [IO.File]::WriteAllText((Join-Path $report 'conpty.stdout.txt'),$t.Text)
    [IO.File]::WriteAllText((Join-Path $report 'conpty.stderr.txt'),$t.Error.ToString())
    @{Environment=$Environment;NativeRelay=[bool]$NativeRelay;ThreadRepetitions=$ThreadRepetitions;Passed=$passed;ExitCode=$exitCode} | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $report 'results.json') -Encoding utf8NoBOM
    $t.Dispose()
    if($terminalWritePath){Remove-Item -LiteralPath $terminalWritePath -ErrorAction SilentlyContinue}
}
