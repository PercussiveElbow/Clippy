# PrivEsc-Clippy
Terribad PrivEsc enumeration script for Windows systems

## Usage

	< I see you're trying to escalate privileges, would you like some help with that? >
		     __
		    /  \
		    |  |
		    @  @
		    |  |
		    || |/
		    || ||
		    |\_/|
		    \___/ 

Command | Info
------------ | -------------                    
clippy.exe enum          | Performs  enumeration
clippy.exe enum report   | Performs enumeration and saves report to disk
clippy.exe download [url]| Downloads a file from given URL 
clippy.exe hax           | Creates new admin, enables RDP, disables firewall (CTF Orientated)

Note: You don't need python on the box you're on to use this. You can just use pyinstaller --onefile clippy.py to pack the python interpreter into an .exe with the script! https://www.pyinstaller.org/
