@echo off

Title Tombstone Cyberpatriot Script

echo Checking if script contains Administrative rights...
	net sessions
	if %errorlevel%==0 (
		echo Success!
			) else (
	echo No admin, please run with Administrative rights...
		pause
	exit
	)

:MainMenu
	CLS
		ECHO =====Tombstone Cyberpatriot=====
		ECHO ===========Instructor===========
		ECHO ============Main Menu============	
		echo Choose An option:
		echo 1. Security Measures (Sub-menu)
		echo 2. Users/Group (Sub-menu)
		echo 3. Programs (Sub-menu)
		echo Q. Quit

		SET INPUT=
		SET /P INPUT=Please select a number:
	
		IF /I '%INPUT%'=='3' goto ProgramMenu	
		IF /I '%INPUT%'=='2' goto UserMenu
		IF /I '%INPUT%'=='1' goto SecurityMenu
		IF /I '%INPUT%'=='Q' goto Quit
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the Main
		echo Menu [1-3] or select 'Q' to quit.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO MainMENU

:SecurityMenu
	CLS
		ECHO =======Tombstone Cyberpatriot=======
		ECHO =============Instructor=============
		ECHO ============Security Menu============	
		echo Choose An option:
		echo 1. Import Hardened Security Policies
		echo 2. Import Original Security Policies
		echo 3. Turn off Auto Logon
		echo 4. Disable Remote Desktop
		echo 5. Set Windows Updates
		echo 6. Best Practices
		echo 7. Disable Weak services (Intensive)
		echo 8. Integrity Scan
		echo 9. Possible Pentrations
		echo Q. Back To Main Menu

		SET INPUT=
		SET /P INPUT=Please select a number:
	
		IF /I '%INPUT%'=='9' goto PossiblePenetrations
		If /I '%INPUT%'=='8' goto IntegrityScan
		IF /I '%INPUT%'=='7' goto WeakServices
		IF /I '%INPUT%'=='6' goto BestPractice
		IF /I '%INPUT%'=='5' goto Updates
		IF /I '%INPUT%'=='4' goto RDP
		IF /I '%INPUT%'=='3' goto Netplwiz
		IF /I '%INPUT%'=='2' goto OriginalPolicies
		IF /I '%INPUT%'=='1' goto HardenedPolicies
		IF /I '%INPUT%'=='Q' goto MainMenu
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the Security
		echo Menu [1-8] or select 'Q' to quit.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO MainMENU

:UserMenu
	CLS

		ECHO ======Tombstone Cyberpatriot======
		ECHO ============Instructor============
		echo ============Users Menu============
		Net User
		echo.
		Net Localgroup
		echo.	
		echo Choose An option:
		echo 1. View a User		
		echo 2. Add a User
		echo 3. Disable a User
		echo 4. Enable a User
		echo 5. Change User Password
		echo 6. Add User to group
		echo 7. List Users of a group
		echo 8. Remove User from group
		echo Q. Back To Main Menu

		SET INPUT=
		SET /P INPUT=Please select a number:
	
		IF /I '%INPUT%'=='8' goto REMGroup
		IF /I '%INPUT%'=='7' goto ListGroupUsers
		IF /I '%INPUT%'=='6' goto AddGroup
		IF /I '%INPUT%'=='5' goto Password
		IF /I '%INPUT%'=='4' goto EnableUser
		IF /I '%INPUT%'=='3' goto DisableUser
		IF /I '%INPUT%'=='2' goto AddUser
		IF /I '%INPUT%'=='1' goto ViewUser
		IF /I '%INPUT%'=='Q' goto MainMenu
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the User
		echo Menu [1-8] or select 'Q' to quit.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO MainMENU	

:ProgramMenu
	CLS

		ECHO =======Tombstone Cyberpatriot=======
		ECHO =============Instructor=============	
		echo ============Program Menu============
		echo Choose An option:
		echo 1. List Programs (May take a Minute)		
		echo 2. Remove Programs
		echo 3. Remove Wireshark
		echo 4. Remove Teamviewer
		echo 5. Remove AngryIP
		echo 6. Remove NPCap
		echo 7. Remove USBPCap
		echo 8. Remove FileZilla
		echo 9. Install MalwareBytes
		echo Q. Back To Main Menu

		SET INPUT=
		SET /P INPUT=Please select a number:

		IF /I '%INPUT%'=='9' goto Malwarebytes	
		IF /I '%INPUT%'=='8' goto RemFileZilla
		IF /I '%INPUT%'=='7' goto RemUSBPCap
		IF /I '%INPUT%'=='6' goto RemNPCap	
		IF /I '%INPUT%'=='5' goto RemAngryip
		IF /I '%INPUT%'=='4' goto RemTeamviewer	
		IF /I '%INPUT%'=='3' goto RemWireshark	
		IF /I '%INPUT%'=='2' goto RemProgram
		IF /I '%INPUT%'=='1' goto ListPrograms
		IF /I '%INPUT%'=='Q' goto MainMenu
	
	CLS

	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the Program
		echo Menu [1-9] or select 'Q' to quit.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
			
	PAUSE > NUL
	GOTO MainMENU


:RemUSBPCap
	REM Uninstall USBPcap
		Echo Uninstall USBPcap exe
			"C:\Program Files\USBPcap\uninstall.exe" /S
		Pause

	GOTO ProgramMenu

:RemNPCap
	REM Uninstall NPCAP
		Echo Uninstall NPCAP exe
			"C:\Program Files\Npcap\uninstall.exe" /S
		Pause

	GOTO ProgramMenu
	
:RemAngryip
	REM Uninstall AngryIP
		Echo Uninstall AngryIP exe
			"C:\Program Files\Angry IP Scanner\uninstall.exe" /S
		Pause

	GOTO ProgramMenu

:RemTeamviewer	
	REM Uninstall TeamViewer
		Echo Uninstall TeamViewer exe
			"C:\Program Files (x86)\TeamViewer\uninstall.exe" /S
		Pause

	GOTO ProgramMenu
	
:RemWireshark	
	REM Uninstall WireShark
		Echo Uninstall WireShark exe version
			"C:\Program Files\Wireshark\uninstall.exe" /S
		Pause
		Echo Uninstall WireShark msi version
			MsiExec.exe /x{F8C728D8-D10A-4171-9DAF-01C0168D0233} /quiet
		Pause

	GOTO ProgramMenu

:RemFileZilla
	REM Uninstall FileZilla
		Echo Uninstall FileZilla exe
			"C:\Program Files\FileZilla FTP Client\uninstall.exe" /S
		Pause

	GOTO ProgramMenu

:PossiblePenetrations
	REM Listing possible penetrations
	cd C:\
	echo "STARTING TO OUTPUT PROCESS FILES DIRECTLY TO THE C:\ DRIVE!"
			wmic process list brief > BriefProcesses.txt
		if %errorlevel%==1 echo Brief Processes failed to write
			wmic process list full >FullProcesses.txt
		if %errorlevel%==1 echo Full Processes failed to write
			wmic startup list full > StartupLists.txt
		if %errorlevel%==1 echo Startup Processes failed to write
			net start > StartedProcesses.txt
		if %errorlevel%==1 echo Started processes failed to write
			reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run  Run.reg
		if %errorlevel%==1 echo Run processes failed to write
	Pause
		
	GoTo SecurityMenu

:RemProgram
		setlocal EnableDelayedExpansion
		wmic product get name
		echo.
		echo  Type Below RequiREMents:
		echo.
		:program
			set /p prog= Type Program Name:
			if [!prog!]==[] goto program
		
		wmic product where name="%prog%" call uninstall 
		pause

	GoTo ProgramMenu
		
:ListPrograms
	wmic product get name
		pause
		
	GoTo ProgramMenu	
	
:ListGroupUsers
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% 
		pause

	GoTo UserMenu
	
:RemGroup
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% %usr% /delete 
		pause

	GoTo UserMenu
	
:AddGroup
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% %usr% /add 
		pause

	GoTo UserMenu
	
:ViewUser
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% 
		pause

	GoTo UserMenu

:Password
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username
		:password
			set /p pwd= Type Password:
			if [!pwd!]==[] goto password
		echo.
		echo Your username is: !usr!
		echo Your password is: !pwd!
		pause

		net user %usr% %pwd% /EXPIRES:NEVER  /PASSWORDCHG:YES 
		pause

	GoTo UserMenu
	
:AddUser
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username
		:password
			set /p pwd= Type Password:
			if [!pwd!]==[] goto password
		echo.
		echo Your username is: !usr!
		echo Your password is: !pwd!
		pause

		net user /add %usr% %pwd% /EXPIRES:NEVER  /PASSWORDCHG:YES /ADD
		WMIC USERACCOUNT WHERE "Name='%usr%'" SET PasswordExpires=TRUE
		pause

	GoTo UserMenu
	
:DisableUser
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% /active:no
		pause

	GoTo UserMenu
	
:EnableUser
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% /active:yes
		pause

	GoTo UserMenu	
	
:BestPractice
	REM Automation found from all over the interwebs, sources unknown, please open issue.
	
	REM Turns on UAC
		reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
		
	REM Disable Administrator and Guest
		net user administrator /active:no
		net user Guest /active:no

	REM Activate Smart Screen
		REM Internet Explorer
			REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "On"
			REG ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\ Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1
		echo Smart Screen Activated. 

	REM REMove all saved credentials
		cmdkey.exe /list > "%TEMP%\List.txt"
		findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
		FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
		del "%TEMP%\*.*" /s /f /q
		set SRVC_LIST=(REMoteAccess Telephony tlntsvr p2pimsvc simptcp fax msftpsvc)
			for %%i in %HITHERE% do net stop %%i
			for %%i in %HITHERE% sc config %%i start= disabled
		netsh advfirewall firewall set rule name="REMote Assistance (DCOM-In)" new enable=no >NUL
		netsh advfirewall firewall set rule name="REMote Assistance (PNRP-In)" new enable=no >NUL
		netsh advfirewall firewall set rule name="REMote Assistance (RA Server TCP-In)" new enable=no >NUL
		netsh advfirewall firewall set rule name="REMote Assistance (SSDP TCP-In)" new enable=no >NUL
		netsh advfirewall firewall set rule name="REMote Assistance (SSDP UDP-In)" new enable=no >NUL
		netsh advfirewall firewall set rule name="REMote Assistance (TCP-In)" new enable=no >NUL
		netsh advfirewall firewall set rule name="Telnet Server" new enable=no >NUL
		netsh advfirewall firewall set rule name="netcat" new enable=no >NUL
			
		reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
		reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
		reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /t
		reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d /1 /f
		reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
		reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
		reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f 
		reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
		reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
	
	REM Services
		echo Showing you the services...
		net start
		echo Now writing services to a file and searching for vulnerable services...
		net start > servicesstarted.txt
		echo This is only common services, not nessecarily going to catch 100%
		REM looks to see if REMote registry is on
		net start | findstr REMote Registry
		if %errorlevel%==0 (
			echo REMote Registry is running!
			echo Attempting to stop...
			net stop REMoteRegistry
			sc config REMoteRegistry start=disabled
			if %errorlevel%==1 echo Stop failed... sorry...
		) else ( 
			echo REMote Registry is already indicating stopped.
		)
	
	REM Clean DNS
		echo Cleaning out the DNS cache...
		ipconfig /flushdns
		echo Writing over the hosts file...
		attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
		echo > C:\Windows\System32\drivers\etc\hosts
		if %errorlevel%==1 echo There was an error in writing to the hosts file (not running this as Admin probably)
	Pause
	
	Goto SecurityMenu
	
:Malwarebytes
	REM Install Malwarebytes
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:directory
			set /p dir= Type directory to MBSetup.exe:
			if [!dir!]==[] goto directory

		%dir%\MBSetup.exe /SP- /SILENT /NOCANCEL
		echo install completed
		pause

	GoTo ProgramMenu

:Netplwiz
	REM Turn off Autologon
		REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f
		echo Autologin turned off, please restart machine
	Pause
	
	GoTo SecurityMenu
				
:RDP	
	REM Turns off RDP
		reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
		REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\REMote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
		reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

	REM Failsafe
		if %errorlevel%==1 netsh advfirewall firewall set service type = REMotedesktop mode = disable
		
	echo REMote Assistance And REMote Desktop are disabled
	pause

	GOTO SecurityMENU
			
:Updates	
	REM Windows auomatic updates
		reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
		net start wuauserc
		net start bits
		net start dosvc
	echo Automatic Updates Set
	pause
	
	GOTO SecurityMenu
				
:OriginalPolicies
	REM Secuirty Policies
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:directory
			set /p dir= Type directory to originalsecpol.inf:
			if [!dir!]==[] goto directory
		
		secedit /configure /db %temp%\temp.sdb /cfg %dir%\originalsecpol.inf
	pause

	GOTO SecurityMenu

:HardenedPolicies	
	REM Secuirty Policies
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:directory
			set /p dir= Type directory to SecuritySettings.inf:
			if [!dir!]==[] goto directory
		
		secedit /configure /db %temp%\temp.sdb /cfg %dir%\securitysettings.inf
	pause

	GOTO SecurityMenu
		
:WeakServices
	REM REMoving good ol' insecure stuff
	echo "DISABLING WEAK SERVICES"
		dism /online /disable-feature /featurename:TelnetClient
		dism /online /disable-feature /featurename:TelnetServer
		dism /online /disable-feature /featurename:IIS-FTPServer
		dism /online /disable-feature /featurename:IIS-FTPSvc
		dism /online /disable-feature /featurename:IIS-FTPExtensibility
		dism /online /disable-feature /featurename:IIS-WebServerRole
		dism /online /disable-feature /featurename:IIS-WebServer
		dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
		dism /online /disable-feature /featurename:IIS-HttpErrors
		dism /online /disable-feature /featurename:IIS-HttpRedirect
		dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
		dism /online /disable-feature /featurename:IIS-NetFxExtensibility
		dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
		dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
		dism /online /disable-feature /featurename:IIS-HttpLogging
		dism /online /disable-feature /featurename:IIS-LoggingLibraries
		dism /online /disable-feature /featurename:IIS-RequestMonitor
		dism /online /disable-feature /featurename:IIS-HttpTracing
		dism /online /disable-feature /featurename:IIS-Security
		dism /online /disable-feature /featurename:IIS-URLAuthorization
		dism /online /disable-feature /featurename:IIS-RequestFiltering
		dism /online /disable-feature /featurename:IIS-IPSecurity
		dism /online /disable-feature /featurename:IIS-Performance
		dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
		dism /online /disable-feature /featurename:IIS-WebServerManagementTools
		dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
		dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
		dism /online /disable-feature /featurename:IIS-Metabase
		dism /online /disable-feature /featurename:IIS-HostableWebCore
		dism /online /disable-feature /featurename:IIS-StaticContent
		dism /online /disable-feature /featurename:IIS-DefaultDocument
		dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
		dism /online /disable-feature /featurename:IIS-WebDAV
		dism /online /disable-feature /featurename:IIS-WebSockets
		dism /online /disable-feature /featurename:IIS-ApplicationInit
		dism /online /disable-feature /featurename:IIS-ASPNET
		dism /online /disable-feature /featurename:IIS-ASPNET45
		dism /online /disable-feature /featurename:IIS-ASP
		dism /online /disable-feature /featurename:IIS-CGI
		dism /online /disable-feature /featurename:IIS-ISAPIExtensions
		dism /online /disable-feature /featurename:IIS-ISAPIFilter
		dism /online /disable-feature /featurename:IIS-ServerSideIncludes
		dism /online /disable-feature /featurename:IIS-CustomLogging
		dism /online /disable-feature /featurename:IIS-BasicAuthentication
		dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
		dism /online /disable-feature /featurename:IIS-ManagementConsole
		dism /online /disable-feature /featurename:IIS-ManagementService
		dism /online /disable-feature /featurename:IIS-WMICompatibility
		dism /online /disable-feature /featurename:IIS-LegacyScripts
		dism /online /disable-feature /featurename:IIS-LegacySnapIn
		dism /online /disable-feature /featurename:TFTP
	Pause
	
	GoTo SecurityMenu
	
:IntegrityScan
	REM START SYS INTEG SCAN!
		echo "STARTING SYSTEM INTERGRITY SCAN"
		echo "If it fails make sure you can access Sfc.exe"
		Sfc.exe /scannow
	Pause

	GOTO SecurityMenu
	
:Quit
CLS

ECHO ==============THANKYOU===============
ECHO -------------------------------------
ECHO ======PRESS ANY KEY TO CONTINUE======

PAUSE>NUL
EXIT