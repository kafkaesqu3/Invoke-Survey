Param(
	[Parameter(Position = 0)]
	[Switch]
    $VersionOverride
)


fuction Invoke-PowershellChecks  {
    #check version script is running as
    $hard_version =  $PSVersionTable.PSVersion.Major
    if ($hard_version -gt 2) {
        if ($VersionOverride -eq $False)
        {
            write-error "[-] ERROR: Powershell version is not 1 or 2"
            #returns "2.0" if installed
            $version2 = (Get-ItemProperty -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine -name PowerShellVersion).PowerShellVersion
            #IF win10, this returns 2.0, but user must download Version v2.0.50727 of the .NET Framework

            #returns version if 3.0+
            $version3plus = (Get-ItemProperty -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine -name PowerShellVersion).PowerShellVersion            

            if ($version2 -eq "2.0") {
                write-host "Version 2.0 is installed. Try restarting powershell.exe with -Version 2"
            $secure_version = $version3plus.split('.')            
            elif ($version3plus -eq "3.0") {
                write-host "Version 3.0 is installed"
            elif ($version3plus -eq "4
            }
            exit
        }
    }

    HKEY_LOCAL_MACHINE\Software\Microsoft\PowerShell\1\Install

}
@"
# if Invoke-PowerShellChecks script fails, quit the script and require override to continue


    Survey (see https://github.com/francisck/DanderSpritz_docs/blob/master/Ops/PyScripts/survey.py)
    * Network interface information (IPs, mac addresses, DNS servers, etc)
    * Operating System Information (Architecture, Version, Platform, Service pack and if Terminal Services is installed)
    * List of when security updates are applied (check for install log)
    * Currently running processes
    * List of hardware drivers
    * Installed software & packages 
            * Installed version(s) of powershell
            * AV Check
            * Log forwarders
            * Check if any are vulnerable to DLL hijacking?
    * All file & folders in the “Program Files” directory
    * Running services
    
    * Checks the security auditing configuration 
            * Audit settings (try to DISABLE audit settings) (see: https://github.com/francisck/DanderSpritz_docs/blob/master/Ops/PyScripts/lib/ops/security/auditing.py)
            * Sysmon?
            * Windows event forwarding?
            * Command line logging?
            * Powershell logging features?
            
    * offer the operator the option to “dork” (temporarily disable) security auditing
    * Network information (routing tables, ARP tables, NetBIOS data, etc)
    * Scheduled tasks
    * Dumps passwords (?)
    * Memory & Disk usage information
    * Connected USB drives and other USB devices
    * Proxy information
    * Files modified recently
    * Check for PSP (see https://github.com/francisck/DanderSpritz_docs/blob/master/Ops/PyScripts/windows/checkpsp.py)
    * monitor for processes, file creations, network connections, and any changes to the system (diffed hourly)
"@

