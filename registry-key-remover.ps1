
if (Test-Path "Registry::HKEY_CLASSES_ROOT\ms-msdt"){
    # Backup the key
    Write-Host "Backing up 'ms-msdt' registry key to current directory" -ForegroundColor Green
    reg export HKEY_CLASSES_ROOT\ms-msdt ms-msdt.reg.bck

    # Delete the key
    Write-Host "Deleting the 'ms-msdt' registry key" -ForegroundColor Red
    reg delete HKEY_CLASSES_ROOT\ms-msdt /f
}
else {
    Write-Warning  "Registry key not found"
} 

