$uptime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

$currentUser = [Environment]::UserName

$networkConfig = Get-NetIPConfiguration | Format-Table -AutoSize | Out-String -Width 4096

$runningProcesses = Get-Process | Select-Object ProcessName, CPU, ID, StartTime | Format-Table -AutoSize | Out-String -Width 4096

$outputFile = "SystemInfo_Report_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt"
$systemInfo = @"
System Uptime: $uptime
Current User: $currentUser
Network Configuration: 
$networkConfig
Running Processes: 
$runningProcesses
"@

$systemInfo | Out-File $outputFile

Write-Host "System information saved to $outputFile"