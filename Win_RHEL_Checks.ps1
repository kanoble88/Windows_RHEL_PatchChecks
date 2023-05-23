<#
    .Updates
3/20/23
    - Added separate function to check Windows Servers.  Windows Server
    does not store KB information in the same place as Windows 10 apparently
4/26/23
    - Fixed? Function to check Windows Server KBs
5/3/23
    - Changed the way the command the RHEL RPM check runs on the guest VM
    - Changed the report the results the RHEL Checks return as well

#>
$ErrorActionPreference = 'SilentlyContinue'
#Variables to Run Script
$scriptPATH = split-path -parent $MyInvocation.MyCommand.Definition

#Get List of VMs from each file
$WinVMs = Get-Content "$scriptPATH\Windows10VMs.txt"
$SvrVMs = Get-Content "$scriptPATH\WindowsServerVMs.txt"
$RHLVms = Get-Content "$scriptPATH\RHELVMs.txt"

#Directory to move CSV and Results & Whatnot
$MoveCSV = "$scriptPATH\PatchCheck.csv"
$Dst = "C:\Temp"
$Trash = "$scriptPATH\Trash"
$Res = "$scriptPATH\Results"

#Variables for RHEL
$ImportRhel = Import-CSV -Path "$scriptPATH\RHELRPMCheck.csv"
$Movescript = "$scriptPATH\RhelPatchCheck.sh"
$RhelPatches = $ImportRhel."RHEL Updated Packages" | foreach {$_ -replace '\s+$', ''}
$Chkkk = @"
rpm -q --queryformat '"%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}"'","'"%{INSTALLTIME:date}"'"\n"
"@

#Install PowerCLI if not installed
<#
  Check if Any VMware PowerCLI Files exist in
  the directories returned from $env:PSModulePath

  If none of the directories return results then 
  PowerCLI will be installed
#>
Function CheckPowerCLI {
$getPaths = ($env:PSModulePath -split ";")
$moveToPath = $getPaths[0]
$gMods = Get-Module VMware.PowerCLI -ListAvailable

if ($null -eq $gMods) {
     Write-host "Not Installed."-ForegroundColor Red
     Write-Host "Installing PowerCLI to $moveToPath"
    Expand-Archive -Path "$scriptPATH\VMware-PowerCLI-12.7.0-20091289.zip" -DestinationPath $moveToPath

    foreach ($file in Get-ChildItem -Path $moveToPath -Recurse) {
        Write-Host "Unblocking $file"
        $file | Unblock-File
    }
}
Else {
 Write-Host "VMware PowerCLI Is Installed. Continuing.`n" -Foreground Green
    }
}
CheckPowerCLI


<#
------ vCenter Address ------
    This is needed in order to connect to vcenter
    Replace the CFE vCenter Info With the one that
    is going to be used to log into and check patches
#>
$VC = "cfevc.cfe.cos"

#Check if C:\Temp exists, if not create it - to save the files
$ChkTmp = @'
if (!(Test-Path -Path C:\Temp)) {
New-Item -Path 'C:\Temp' -ItemType Directory
}
'@


$StartProgCheck = @'
    $CSV = Import-CSV "C:\Temp\PatchCheck.csv"
    #$CSV

    #$scriptPATH = split-path -parent $MyInvocation.MyCommand.Definition
    Function Get-ReggyKeyKey {
        #Parse Win10 Registry for KBs	
        Param(
            [Parameter(Mandatory = $true)] [String]$Name
        )
        #$ErrorActionPreference = 'SilentlyContinue'
        if (!([Diagnostics.Process]::GetCurrentProcess().Path -match '\\syswow64\\')) {
            $unistallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
            $unistallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"        
            @(
                if (Test-Path "HKLM:$unistallWow6432Path" ) { Get-ChildItem "HKLM:$unistallWow6432Path" }
                if (Test-Path "HKLM:$unistallPath" ) { Get-ChildItem "HKLM:$unistallPath" }
                if (Test-Path "HKCU:$unistallWow6432Path") { Get-ChildItem "HKCU:$unistallWow6432Path" }
                if (Test-Path "HKCU:$unistallPath" ) { Get-ChildItem "HKCU:$unistallPath" }
            ) |
            ForEach-Object { Get-ItemProperty $_.PSPath } | 
            Where-Object {
                $_.DisplayName -and
                $_.DisplayVersion } |
            Where { $_.DisplayName -like "*$Name*" } | Select DisplayName, DisplayVersion 
        } 
        else {
            "You are running 32-bit Powershell on 64-bit system. Please run 64 - bit Powershell instead." | Write-Host -ForegroundColor Red    
        }
    }

function DoProgstuff {
    $Erray = @()
    $GetProgCSV = $CSV | Select ProgName, ProgVer | Where-Object { $_.PSObject.Properties.Value -ne '' }
    foreach ($Prog in $GetProgCSV) {
    #$Prog
        $GetRegKey = Get-ReggyKeyKey -Name $Prog.ProgName
        If ($Prog.ProgVer -eq $GetRegKey.DisplayVersion) {
            $obj = new-object psobject -Property @{
                System           = Hostname
                Program          = $Prog.ProgName 
                VersionChecked   = $Prog.ProgVer
                VersionInstalled = $GetRegKey.DisplayVersion
                Installed        = "Yes"
            }
        }
        elseif ($Prog.ProgVer -ne $GetRegKey.DisplayVersion) {
            $obj = new-object psobject -Property @{
                System           = Hostname
                Program          = $Prog.ProgName
                VersionChecked   = $Prog.ProgVer
                VersionInstalled = $GetRegKey.DisplayVersion
                Installed        = "No"
            }
        }
        $Erray += $obj
    } $Erray | Select System,Program,Installed,VersionInstalled,VersionChecked 

}
DoProgstuff | ConvertTo-Csv -NotypeInformation 
'@

#Win10 KB Checks
$StartKBCheck = @'
    $CSV = Import-CSV "C:\Temp\PatchCheck.csv"
    #$CSV
Function GetKBBaby {
    #CSV Path - Can Probably have it prompt for it
    $GetKBCSV = $CSV | Select KBName | Where-Object { $_.PSObject.Properties.Value -ne '' }
    #Registry Path to Look for the KB's
    $RegPath = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\' -Recurse | Get-ItemProperty
    #Create a user friendly way to search the registry
    $Reg = $RegPath.InstallLocation
    #Array for KBs
    $ListKBs=@()
    
    Foreach($KBS in $GetKBCSV.KBName) {
        If ($Reg -like "*$KBS*") {
            $KBProps = New-Object PSObject -Property @{
                System    = Hostname
                KBNumber  = $KBS
                Installed = "Yes"
        } 
    } Elseif ($Reg -notlike "*$KBS*") {
            $KBProps = New-Object PSObject -Property @{
                System    = Hostname
                KBNumber  = $KBS
                Installed = "No"
            } 
        }
        $ListKBs += $KBProps
      }
    $ListKBs| Select System,KBNumber,Installed  
    }
GetKBBaby | ConvertTo-Csv -NotypeInformation 
'@

#Windows Server KB Checks
$SvrKBChecks = @'
    #$ErrorActionPreference = 'SilentlyContinue'
    $SvrArray = @()
    $WinSvr = @()
    $CSV = Import-CSV "C:\Temp\PatchCheck.csv"
    $CSV2 = $CSV | Select SvrKBName | Where-Object { $_.PSObject.Properties.Value -ne '' }
    $PatchPath = "\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\"      
    @(
        if (Test-Path "HKLM:$PatchPath" ) { Get-ChildItem "HKLM:$PatchPath" -Recurse }
    ) |
    ForEach-Object { Get-ItemProperty $_.PSPath } | 
    Where-Object {
        $_.InstallName  
    } | 
    Where { $_.InstallName -like "*KB*" } |
    % {
        $obj = new-object psobject -Property @{
            Name        = $_.InstallName
         } 
        $SvrArray += $obj
    } 
 
    $svrChk = $SvrArray.Name
    foreach ($kb in $CSV2.SvrKBName) {
        If ($svrChk -like "*$kb*") {
            $SvrKB = New-Object PSObject -Property @{
                HostName  = $env:COMPUTERNAME
                KBNumber  = $kb
                Installed = "Yes"
            }
        }
        Elseif ($svrChk -notlike "*$kb*") {
            $SvrKB = New-Object PSObject -Property @{
                HostName  = $env:COMPUTERNAME
                KBNumber  = $kb
                Installed = "No"
            }

        }
        $WinSvr += $SvrKB
    }
    $WinSvr | select HostName, KBNumber, Installed | Sort -Descending Installed | ConvertTo-CSV -NTI
'@

#Rhel Checks
$CheckRHELRpms = @'
hostname
cd /tmp
chmod +x RhelPatchCheck.sh
./RhelPatchCheck.sh >> Temp_Patches.txt
cat Temp_Patches.txt > "$HOSTNAME"_PatchReport.txt
rm -f Temp_Patches.txt
rm -f RhelPatchCheck.sh
'@

#VMCleanUp - Clean Up Files that were created
$WinVMCleanUp = @'
remove-item C:\Temp\PatchCheck_Remote.ps1 -ErrorAction SilentlyContinue
remove-item C:\Temp\PatchCheck.csv -ErrorAction SilentlyContinue
'@

$RhCleanUp = @'
cd /tmp
rm -f *_PatchReport.txt
'@


#vCenter Connection
$VCUser = Read-Host "VC Username"
$VCPaswd = read-host "VC PW:" -AsSecureString
$VCCred = New-Object System.Management.Automation.PSCredential $VCUser, $VCPaswd
Connect-VIServer $VC -Credential $VCCred


#Ask About Login Stuff
$VMPW = Read-Host "`nIs the login information for the Windows VMs different than the one used to sign into vCenter? (Y\N)" 
Switch ($VMPW) {
    Y {
        #If Account For VM is different than vCenter Prompt for Credentials
        #Windows VM Login Info
        $User = read-Host "Windows Username"
        $Pswd = Read-Host "Windows Password" -AsSecureString
        #RHEL VM Login Info
        $LUser = read-Host "Enter Linux Username"
        $LPswd = Read-Host "Enter Linux Password" -AsSecureString

Function CheckPatches {
            #If Account for Vms are Not different than vCenter Continue - Except RHEL Login
            #Check Program Updates and Compare to CSV ----- Win 10
            $CheckProgUpdates = foreach ($VM in $WinVMs) {
                Write-Host "--- Checking That C:\Temp directory exists: $VM"
                $ChkTemp = (Invoke-VMScript –VM $VM `
                        -GuestUser $User `
                        -GuestPassword $Pswd `
                        -ScriptText $ChkTmp).ScriptOutput
                $ChkTemp

                Write-Host "Copying CSV File to" $VM
                Get-Item $MoveCSV | 
                Copy-VMGuestFile -Destination $Dst `
                    -VM $VM `
                    -LocalToGuest -GuestUser $User `
                    -GuestPassword $Pswd -Force

                Write-Host "--- Program Checks: $VM"
                $ChkVM = (Invoke-VMScript –VM $VM `
                        -GuestUser $User `
                        -GuestPassword $Pswd `
                        -ScriptText $StartProgCheck).ScriptOutput
                $ChkVM | Out-File $Trash\Temp_Win10ProgChecks.csv -Append
            } $CheckProgUpdates 
            $ExportProgResults = Import-CSV $Trash\Temp_Win10ProgChecks.csv | Export-CSV $Res\Win10_ProgChecks.csv -Delimiter "," -NTI 
            $ExportProgResults

            #Check KBs on CSV Against Those in Registry ----- Win 10
            $CheckKBInstalled = foreach ($VM in $WinVMs) {
                Write-Host "--- KB Checks: $VM"
                $ChkVM2 = (Invoke-VMScript –VM $VM `
                        -GuestUser $User `
                        -GuestPassword $Pswd `
                        -ScriptText $StartKBCheck).ScriptOutput
                $ChkVM2 | Out-File $Trash\Temp_Win10KBChecks.csv -Append
            } $CheckKBInstalled
            $ExportKBResults = Import-CSV $Trash\Temp_Win10KBChecks.csv | Export-CSV $Res\Win10_KBChecks.csv -Delimiter "," -NTI 
            $ExportKBResults

            #Check Program Updates ----- Win Server
            $CheckSvrProgUpdates = foreach ($VM in $SvrVMs) {

                Write-Host "--- Checking That C:\Temp directory exists: $VM"
                $ChkTemp = (Invoke-VMScript –VM $VM `
                        -GuestUser $User `
                        -GuestPassword $Pswd `
                        -ScriptText $ChkTmp).ScriptOutput
                $ChkTemp 

                Write-Host "Copying CSV File to" $VM
                Get-Item $MoveCSV | 
                Copy-VMGuestFile -Destination $Dst `
                    -VM $VM `
                    -LocalToGuest -GuestUser $User `
                    -GuestPassword $Pswd -Force
                Write-Host "--- Program Checks: $VM"

                $ChkVM3 = (Invoke-VMScript –VM $VM `
                        -GuestUser $User `
                        -GuestPassword $Pswd `
                        -ScriptText $StartProgCheck).ScriptOutput
                $ChkVM3 | Out-File $Trash\Temp_WinSvrProgChecks.csv -Append
            } $CheckSvrProgUpdates 
            $ExportSvrProgResults = Import-CSV $Trash\Temp_WinSvrProgChecks.csv | Export-CSV $Res\WinSvr_ProgChecks.csv -Delimiter "," -NTI 
            $ExportSvrProgResults

            #Check KB's ----- Win Server
            $WinSvrKBCheck = foreach ($VM in $SvrVMs) {
                Write-Host "--- Checking That C:\Temp directory exists: $VM"
                $ChkTemp = (Invoke-VMScript –VM $VM `
                        -GuestUser $User `
                        -GuestPassword $Pswd `
                        -ScriptText $ChkTmp).ScriptOutput
                $ChkTemp

                #    $guest = Get-VMGuest $VM
                Write-Host "Starting" $VM
                Get-Item $MoveCSV | 
                Copy-VMGuestFile -Destination $Dst `
                    -VM $VM `
                    -LocalToGuest -GuestUser $User `
                    -GuestPassword $Pswd -Force

                $Check = (Invoke-VMScript –VM $VM `
                        -GuestUser $User `
                        -GuestPassword $Pswd `
                        -ScriptText $SvrKBChecks).ScriptOutput
                $Check | Out-File $Trash\Temp_WinSvrKBChecks.csv -Append
            } $WinSvrKBCheck
            $ExportSvrKBResults = Import-CSV $Trash\Temp_WinSvrKBChecks.csv | Export-CSV $Res\WinSvr_KBChecks.csv -Delimiter "," -NTI 
            $ExportSvrKBResults
 
            #Check RPMs for RHEL
            $RHELCheck = foreach ($VM in $RHLVms) {  
             $ParsePatches = foreach ($Patch in $RhelPatches) {
                                $CheckCmd = "$Chkkk $Patch"
                                $CheckScript += $CheckCmd | ForEach-Object {
                    $_ -replace ' [0-9]:','-' `
                       -replace  '.x86_64','' `
                       -replace '.i686','' `
                       -replace '.noarch',''
                    } |Out-File "$scriptPATH\RhelPatchCheck.sh" -Append
                                #$CheckScript
                            } $ParsePatches
				
                $file = "$scriptPATH\RhelPatchCheck.sh"
                ((Get-Content $file) -join "`n") + "`n" | Set-Content -NoNewline $file

                #Copy Shell Script to RHEL VMs
                Get-Item $MoveScript | Copy-VMGuestFile -Destination "/tmp" `
                    -VM $VM `
                    -LocalToGuest -GuestUser $LUser `
                    -GuestPassword $LPswd -Force

                #$CheckScript
                $RHCheck = Invoke-VMScript -VM $VM `
                    -ScriptText $CheckRHELRpms `
                    -GuestUser $LUser `
                    -GuestPassword $LPswd
                $RHCheck

                #Copy Patch Report From Remote VM to Localhost
                Copy-VMGuestFile -Source "/tmp/*_PatchReport.txt" `
                    -Destination $scriptPATH `
                    -VM $VM `
                    -GuestToLocal -GuestUser $LUser `
                    -GuestPassword $LPswd -Force
                
                #Parse Patch Output files and convert them to .csv files    
                $files = Get-ChildItem -Path $scriptPATH -Filter *.txt
                ForEach ($file in $files) {
                    $Data = Import-Csv $fle.FullName -Delimiter ',' -Header "RPM","InstallDate"
                    $Data | Export-Csv ([io.path]::ChangeExtension($file.Fullname, '.csv')) -NoType -Force
                }
            }
            $RHELCheck
            #CleanUp files created from the script
Function StartRemoteCleanUp {
                Write-Host "Starting File Clean Up.."
                $Win10CleanUp = foreach ($VM in $WinVMs) {
                    Write-Host "`nCleaning $VM..." 
                    $Clean = (Invoke-VMScript –VM $VM `
                            -GuestUser $User `
                            -GuestPassword $Pswd `
                            -ScriptText $WinVMCleanUp).ScriptOutput
                    $Clean
                } $Win10CleanUp 
                $WinSvrCleanUp = foreach ($VM in $SvrVMs) {
                    Write-Host "`nCleaning $VM..." 
                    $Clean = (Invoke-VMScript –VM $VM `
                            -GuestUser $User `
                            -GuestPassword $Pswd `
                            -ScriptText $WinVMCleanUp).ScriptOutput
                    $Clean
                } $WinSvrCleanUp
                $RhClean = foreach ($VM in $RHLVms) {
                    Write-Host "`nCleaning $VM..." 
                    $Clean = Invoke-VMScript -VM $VM `
                        -ScriptText $RhCleanUp `
                        -GuestUser $LUser `
                        -GuestPassword $LPswd
                    $Clean
                } $RhClean
                Write-Host "Cleaning Local Files"
                remove-item $scriptPATH\Trash\*.*
                remove-item $scriptPATH\*_PatchReport.txt
                remove-item $scriptPATH\RhelPatchCheck.sh
        
        Write-Output "Disconnecting from vCenter"
        Disconnect-VIServer -Confirm:$False     
}
        }
        CheckPatches
        Write-Output "Complete."
        Write-Host "Results saved to the following directory: $scriptPATH\Results"
        StartRemoteCleanUp
     
    }
    N {
        #RHEL Login Info
        $LUser = read-Host "`nEnter Linux Username"
        $LPswd = Read-Host "Enter Linux Password" -AsSecureString
        Function CheckPatches {
            #If Account for Vms are Not different than vCenter Continue - Except RHEL Login         
            #Check Program Updates and Compare to CSV ----- Win 10
            $CheckProgUpdates = foreach ($VM in $WinVMs) {
            #Check for C:\Temp Directory
                $ChkTemp = (Invoke-VMScript –VM $VM `
                        -GuestCredential $VCCred `
                        -ScriptText $ChkTmp).ScriptOutput
                $ChkTemp
 
                Write-Host "Copying CSV File to" $VM
                Get-Item $MoveCSV | 
                Copy-VMGuestFile -Destination $Dst `
                    -VM $VM `
                    -LocalToGuest -GuestCredential $VCCred -Force

                Write-Host "--- Program Checks: $VM"
                $ChkVM = (Invoke-VMScript –VM $VM `
                        -GuestCredential $VCCred `
                        -ScriptText $StartProgCheck).ScriptOutput
                $ChkVM | Out-File $Trash\Temp_Win10ProgChecks.csv -Append
            } $CheckProgUpdates 
            $ExportProgResults = Import-CSV $Trash\Temp_Win10ProgChecks.csv | Export-CSV $Res\Win10_ProgChecks.csv -Delimiter "," -NTI 
            $ExportProgResults

            #Check KBs on CSV Against Those in Registry ----- Win 10
            $CheckKBInstalled = foreach ($VM in $WinVMs) {
                Write-Host "--- KB Checks: $VM"
                $ChkVM2 = (Invoke-VMScript –VM $VM `
                        -GuestCredential $VCCred `
                        -ScriptText $StartKBCheck).ScriptOutput
                $ChkVM2 | Out-File $Trash\Temp_Win10KBChecks.csv -Append
            } $CheckKBInstalled
            $ExportKBResults = Import-CSV $Trash\Temp_Win10KBChecks.csv | Export-CSV $Res\Win10_KBChecks.csv -Delimiter "," -NTI 
            $ExportKBResults

            #Check Program Updates and Compare to CSV ----- Win 10
            $CheckSvrProgUpdates = foreach ($VM in $SvrVMs) {
                Write-Host "--- Checking That Temp directory exists: $VM"
                $ChkTemp = (Invoke-VMScript –VM $VM `
                        -GuestCredential $VCCred `
                        -ScriptText $ChkTmp).ScriptOutput
                $ChkTemp

                Write-Host "Copying CSV File to" $VM
                Get-Item $MoveCSV | 
                Copy-VMGuestFile -Destination $Dst `
                    -VM $VM `
                    -LocalToGuest -GuestCredential $VCCred -Force

                Write-Host "--- Program Checks: $VM"
                $ChkVM = (Invoke-VMScript –VM $VM `
                        -GuestCredential $VCCred `
                        -ScriptText $StartProgCheck).ScriptOutput
                $ChkVM | Out-File $Trash\Temp_WinSvrProgChecks.csv -Append
            } $CheckSvrProgUpdates 
            $ExportSvrProgResults = Import-CSV $Trash\Temp_WinSvrProgChecks.csv | Export-CSV $Res\WinSvr_ProgChecks.csv -Delimiter "," -NTI 
            $ExportSvrProgResults

            #Check KB's ----- Win Server Need to Fix Creds
            $WinSvrKBCheck = foreach ($VM in $SvrVMs) {
                $Check = (Invoke-VMScript –VM $VM `
                    -GuestCredential $VCCred `
                    -ScriptText $SvrKBChecks).ScriptOutput
                $Check | Out-File $Trash\Temp_WinSvrKBChecks.csv -Append
            } $WinSvrKBCheck
            $ExportSvrKBResults = Import-CSV $Trash\Temp_WinSvrKBChecks.csv | Export-CSV $Res\WinSvr_KBChecks.csv -Delimiter "," -NTI 
            $ExportSvrKBResults
 
            #Parse the patches and remove the trash extra data that is in there for some reason       
            #Check RPMs for RHEL
            $RHELCheck = foreach ($VM in $RHLVms) {  
            
              $ParsePatches = foreach ($Patch in $RhelPatches) {
                                $CheckCmd = "$Chkkk $Patch"
                                $CheckScript += $CheckCmd | ForEach-Object {
                    $_ -replace ' [0-9]:','-' `
                       -replace  '.x86_64','' `
                       -replace '.i686','' `
                       -replace '.noarch',''
                    } |Out-File "$scriptPATH\RhelPatchCheck.sh" -Append
                                #$CheckScript
                            } $ParsePatches

                $file = "$scriptPATH\RhelPatchCheck.sh" 
                ((Get-Content $file) -join "`n") + "`n" | Set-Content -NoNewline $file

                #Copy Shell Script to RHEL VMs
                Get-Item $MoveScript | Copy-VMGuestFile -Destination "/tmp" `
                    -VM $VM `
                    -LocalToGuest -GuestUser $LUser `
                    -GuestPassword $LPswd -Force

                #$CheckScript to start checking RPMs listed in CSV
                $RHCheck = (Invoke-VMScript -VM $VM `
                    -ScriptText $CheckRHELRpms `
                    -GuestUser $LUser `
                    -GuestPassword $LPswd).ScriptOutput
                $RHCheck
    
                #Copy Patch Report From Remote VM to Localhost
                Copy-VMGuestFile -Source "/tmp/*_PatchReport.txt" `
                    -Destination $scriptPATH `
                    -VM $VM `
                    -GuestToLocal -GuestUser $LUser `
                    -GuestPassword $LPswd -Force
                
                #Parse Patch Output files and convert them to .csv files   
                $files = Get-ChildItem -Path $scriptPATH | Where {$_.FullName -like "*PatchReport.txt*"}
                ForEach ($fle in $files) {
                    $Data = Import-Csv $fle.FullName -Delimiter ',' -Header "RPM","InstallDate"
                    $Data | Export-Csv ([io.path]::ChangeExtension($fle.Fullname, '.csv')) -NoType -Force                  
                }     
            } 
            Get-ChildItem –Path $scriptPATH | Where {$_.FullName -like "*PatchReport.csv*"} | Move-Item -Destination "$scriptPATH\Results"
             $RHELCheck


        }
Function StartRemoteCleanUp {
                Write-Host "Starting File Clean Up.."
                $Win10CleanUp = foreach ($VM in $WinVMs) {
                    Write-Host "Cleaning $VM..." 
                    $Clean = (Invoke-VMScript –VM $VM `
                            -GuestCredential $VCCred `
                            -ScriptText $WinVMCleanUp).ScriptOutput
                    $Clean
                } $Win10CleanUp 
                $WinSvrCleanUp = foreach ($VM in $SvrVMs) {
                    Write-Host "Cleaning $VM..." 
                    $Clean = (Invoke-VMScript –VM $VM `
                            -GuestCredential $VCCred `
                            -ScriptText $WinVMCleanUp).ScriptOutput
                    $Clean
                } $WinSvrCleanUp
                $RhClean = foreach ($VM in $RHLVms) {
                    Write-Host "Cleaning $VM..." 
                    $Clean = (Invoke-VMScript -VM $VM `
                        -ScriptText $RhCleanUp `
                        -GuestUser $LUser `
                        -GuestPassword $LPswd).ScriptOutput
                    $Clean
                } $RhClean
                Write-Host "Cleaning Local Files"
                remove-item $scriptPATH\Trash\*.* -ErrorAction SilentlyContinue
                remove-item $scriptPATH\*_PatchReport.txt -ErrorAction SilentlyContinue
                remove-item $scriptPATH\RhelPatchCheck.sh -ErrorAction SilentlyContinue
        
                Write-Output "Complete."
                Write-Host "Results saved to the following directory: $scriptPATH\Results"
                Write-Output "`nDisconnecting from vCenter"
                Disconnect-VIServer -Confirm:$False
}
        CheckPatches 
        StartRemoteCleanUp

    }
}