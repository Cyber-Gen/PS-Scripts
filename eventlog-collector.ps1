$logNames = @("Security", "Application", "System")

# Define the time range (last 7 days)
$startTime = (Get-Date).AddDays(-7)
$endTime = Get-Date

$outputDir = "EventLogs_" + (Get-Date -Format "yyyyMMdd_HHmmss")
New-Item -Path $outputDir -ItemType Directory

foreach ($log in $logNames) {
    $filter = @{
        LogName = $log
        StartTime = $startTime
        EndTime = $endTime
    }
    
    $events = Get-WinEvent -FilterHashtable $filter
    $outputFile = Join-Path $outputDir ("$log" + ".txt")
    $events | Format-Table -AutoSize | Out-String -Width 4096 | Out-File $outputFile
}

Write-Host "Event logs saved in directory: $outputDir"