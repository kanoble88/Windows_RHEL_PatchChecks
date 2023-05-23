# Windows_RHEL_PatchChecks
Checks Patches Installed on Windows/RHEL VMs hosted in vSphere

Needs PowerCLI installed - If not installed the script should install it from the local version
Needs RHEL Root Login
Needs vSphere Credentials and Windows login with admin rights

This is pretty much tailored to work on the environment I use and will most likely require some changes
to work with other environments, so you'll probably need to comment out the $ErrorActionPreference if you
need to troubleshoot.

All VM OS's are separated into their own files, so Windows 10, Windows Server & RHEL VM Names all go in their own files

The PatchCheck.csv file is where you put the Windows KBs/App Update Versions
	- So Windows 10 KB's get listed under the KBName Column
	- Windows 10 Program Updates go under ProgName & ProgVer
	- Windows Server KB's go under the SvrKbName Column
	- Windows Server Program Updates go under the SvrProgName & SvrProgVer
		- They are like this due to the different locations each OS lists KB's
			and whatnot, Windows 10 lists them in a different Registry location
			than Windows Server does
	- RHEL list the RPM's that need to be checked in the RHELRPMCheck.csv file, they go under 'RHEL Updated Packages'
The script outputs the results into the trash folder then combines the results, then moves the combined results into
the results folder, then deletes the trash.
