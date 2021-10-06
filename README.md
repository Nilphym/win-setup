## What this script does?

* Strips Windows 10 of many pre-built features, tracking and apps  
*(removes Windows Store, won't remove Calculator)*
* Enables only security updates
* Cleans taskbar
* Restores good old Windows Photo Viewer and sets it as default
* Downloads Snappy which is open source, best driver installer

For more detailed description read comments in [win-setup.ps1](win-setup.ps1) file


## How to run script?

Run Powershell with Admin privileges paste:  
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/JCdGq'))
```

When the script finishes its job, run Snappy Driver Installer which will be downloaded in the last step of the script in the same folder.


## Important note

The script is intended to run on freshly installed and updated Windows 10.  
Do not run the script if you didn't update the os.
