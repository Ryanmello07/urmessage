# THROWAWAY (ruling R31): the deny table, with the readers started from THIS pwsh.
# Usage: pwsh -File table.ps1 <denyprobe.exe>
param([string]$Probe)
$me = (whoami).Trim()
foreach ($location in @(@('user temp', [System.IO.Path]::GetTempPath()), @('RUNNER_TEMP', $env:RUNNER_TEMP))) {
    foreach ($mask in @('(R)', '(RD)')) {
        $dir = Join-Path $location[1] ("denyprobe-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $file = Join-Path $dir 'epoch'
        Set-Content -Path $file -Value 'the octets of an epoch state' -NoNewline
        Write-Output "=== pwsh | $($location[0]) | $mask | $file"
        icacls $file /deny "${me}:$mask" | Out-Null
        Write-Output "  icacls listing:"
        icacls $file | ForEach-Object { "    $_" }
        & $Probe $file
        try { Get-Content -Path $file -ErrorAction Stop | Out-Null; Write-Output "  Get-Content: READ (no error)" } catch { Write-Output "  Get-Content: $($_.Exception.Message)" }
        icacls $file /remove:d $me | Out-Null
        Remove-Item -Recurse -Force $dir
    }
}
