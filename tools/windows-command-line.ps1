function ConvertTo-WindowsCommandLine([string[]]$Arguments) {
    ($Arguments | ForEach-Object {
        $escaped = [string]$_ -replace '(\\*)"', '$1$1\"' -replace '(\\+)\z', '$1$1'
        '"' + $escaped + '"'
    }) -join ' '
}
