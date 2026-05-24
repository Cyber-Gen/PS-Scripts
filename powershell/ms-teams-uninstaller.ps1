function unInstallTeams($path) {

    $clientInstaller = "$($path)\Update.exe"
    
     try {
          $process = Start-Process -FilePath "$clientInstaller" -ArgumentList "--uninstall /s" -PassThru -Wait -ErrorAction STOP
  
          if ($process.ExitCode -ne 0)
      {
        Write-Error "UnInstallation failed with exit code  $($process.ExitCode)."
          }
      }
      catch {
          Write-Error $_.Exception.Message
      }
  
  }
  
  # Remove Teams Machine-Wide Installer
  Write-Host "Removing Teams Machine-wide Installer" -ForegroundColor Yellow

  $machineWideRemoved = $false

  # Tier 1: Get-Package (PackageManagement) - modern, fast path
  try {
      $pkg = Get-Package -Name "Teams Machine-Wide Installer" -ErrorAction SilentlyContinue
      if ($null -ne $pkg) {
          Write-Host "Found Teams Machine-Wide Installer via Get-Package. Uninstalling..." -ForegroundColor Yellow
          $pkg | Uninstall-Package -Force -ErrorAction Stop | Out-Null
          $machineWideRemoved = $true
      }
      else {
          Write-Host "Teams Machine-Wide Installer not found via Get-Package. Trying registry..." -ForegroundColor Cyan
      }
  }
  catch {
      Write-Warning "Get-Package tier failed: $($_.Exception.Message). Falling through to registry tier."
  }

  # Tier 2: Registry uninstall string
  if (-not $machineWideRemoved) {
      try {
          $uninstallKeys = @(
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
          )
          $entry = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
              Where-Object { $_.DisplayName -eq "Teams Machine-Wide Installer" } |
              Select-Object -First 1

          if ($null -ne $entry -and -not [string]::IsNullOrWhiteSpace($entry.UninstallString)) {
              Write-Host "Found Teams Machine-Wide Installer via registry. Uninstalling..." -ForegroundColor Yellow
              $uninstallString = $entry.UninstallString.Trim()

              # Parse the uninstall string - typically "MsiExec.exe /X{GUID}" or "MsiExec.exe /I{GUID}"
              $exePath = $null
              $exeArgs = $null
              if ($uninstallString.StartsWith('"')) {
                  $endQuote = $uninstallString.IndexOf('"', 1)
                  $exePath = $uninstallString.Substring(1, $endQuote - 1)
                  $exeArgs = $uninstallString.Substring($endQuote + 1).Trim()
              }
              else {
                  $firstSpace = $uninstallString.IndexOf(' ')
                  if ($firstSpace -gt 0) {
                      $exePath = $uninstallString.Substring(0, $firstSpace)
                      $exeArgs = $uninstallString.Substring($firstSpace + 1).Trim()
                  }
                  else {
                      $exePath = $uninstallString
                      $exeArgs = ''
                  }
              }

              # Normalize /I to /X for an uninstall, and append silent/no-restart switches.
              $exeArgs = $exeArgs -replace '(?i)(^|\s)/I(?=\{)', '$1/X'
              if ($exeArgs -notmatch '(?i)/qn')        { $exeArgs = "$exeArgs /qn".Trim() }
              if ($exeArgs -notmatch '(?i)/norestart') { $exeArgs = "$exeArgs /norestart".Trim() }

              # If the parsed exe is msiexec (with or without path), call msiexec.exe directly.
              $leaf = try { Split-Path -Leaf $exePath } catch { $exePath }
              if ($leaf -match '(?i)^msiexec(\.exe)?$') {
                  $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $exeArgs -Wait -PassThru -ErrorAction Stop
              }
              else {
                  $proc = Start-Process -FilePath $exePath -ArgumentList $exeArgs -Wait -PassThru -ErrorAction Stop
              }

              if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                  $machineWideRemoved = $true
              }
              else {
                  Write-Warning "Registry-based uninstall returned exit code $($proc.ExitCode). Falling through to CIM tier."
              }
          }
          else {
              Write-Host "Teams Machine-Wide Installer not found in registry. Trying CIM..." -ForegroundColor Cyan
          }
      }
      catch {
          Write-Warning "Registry tier failed: $($_.Exception.Message). Falling through to CIM tier."
      }
  }

  # Tier 3: Get-CimInstance Win32_Product - SLOW; triggers MSI reconfiguration on every installed package.
  # Kept only as a last-resort fallback when Get-Package and registry lookups both fail.
  if (-not $machineWideRemoved) {
      try {
          $machineWide = Get-CimInstance -ClassName Win32_Product -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -eq "Teams Machine-Wide Installer" }
          if ($null -ne $machineWide) {
              Write-Host "Found Teams Machine-Wide Installer via CIM. Uninstalling..." -ForegroundColor Yellow
              $result = Invoke-CimMethod -InputObject $machineWide -MethodName Uninstall -ErrorAction Stop
              if ($null -ne $result -and $result.ReturnValue -eq 0) {
                  $machineWideRemoved = $true
              }
              else {
                  Write-Warning "CIM uninstall returned non-zero result: $($result.ReturnValue)"
              }
          }
          else {
              Write-Host "Teams Machine-Wide Installer not found via CIM." -ForegroundColor Cyan
          }
      }
      catch {
          Write-Warning "CIM tier failed: $($_.Exception.Message)"
      }
  }

  if (-not $machineWideRemoved) {
      Write-Host "Teams Machine-Wide Installer not found" -ForegroundColor Cyan
  }
  
  # Remove Teams for Current Users
  $localAppData = "$($env:LOCALAPPDATA)\Microsoft\Teams"
  $programData = "$($env:ProgramData)\$($env:USERNAME)\Microsoft\Teams"
  
  
  If (Test-Path "$($localAppData)\Current\Teams.exe") 
  {
    unInstallTeams($localAppData)
      
  }
  elseif (Test-Path "$($programData)\Current\Teams.exe") {
    unInstallTeams($programData)
  }
  else {
    Write-Warning  "Teams installation not found"
  }