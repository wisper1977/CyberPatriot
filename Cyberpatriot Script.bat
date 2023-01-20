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
		ECHO ===========Main Menu============	
		echo Choose An option:
		echo 1. Security Measures (Sub-menu)
		echo 2. Users/Group (Sub-menu)
		echo 3. Programs (Sub-menu)
		echo Q. Quit

		SET INPUT=
		SET /P INPUT=Please select a number:
	
		IF /I '%INPUT%'=='3' goto ProgramMenu	
		IF /I '%INPUT%'=='2' goto UserGroupMenu
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

:UserGroupMenu
	CLS
		ECHO =====Tombstone Cyberpatriot=====
		ECHO ===========Instructor===========
		echo ========User/Group Menu=========
		echo.	
		echo Choose An option:
		echo 1. User Menu		
		echo 2. Groups Menu
		echo Q. Quit
		SET INPUT=
		SET /P INPUT=Please select a number:
	
		IF /I '%INPUT%'=='2' goto GroupMenu
		IF /I '%INPUT%'=='1' goto UserMenu
		IF /I '%INPUT%'=='Q' goto Quit
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the User
		echo Menu [1-2] or select 'Q' to quit.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO UserGroupMenu

:UserMenu
	CLS
		ECHO =====Tombstone Cyberpatriot=====
		ECHO ===========Instructor===========
		echo ===========Users Menu===========
		echo.
		Net User
		echo.	
		echo Choose An option:
		echo 1. View a User		
		echo 2. Add a User
		echo 3. Disable a User
		echo 4. Enable a User
		echo 5. Change User Password
		echo 6. Change All Users Passwords
		echo Q. Back To User/Group Menu
		SET INPUT=
		SET /P INPUT=Please select a number:

		IF /I '%INPUT%'=='6' goto AllPassword	
		IF /I '%INPUT%'=='5' goto Password
		IF /I '%INPUT%'=='4' goto EnableUser
		IF /I '%INPUT%'=='3' goto DisableUser
		IF /I '%INPUT%'=='2' goto AddUser
		IF /I '%INPUT%'=='1' goto ViewUser
		IF /I '%INPUT%'=='Q' goto UserGroupMenu
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the User
		echo Menu [1-6] or select 'Q' to User/Group Menu.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO UserMenu

:ViewUser
	CLS
	Net user
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr%

		IF %errorlevel% neq 0 Set Command="View User"
		IF %errorlevel% neq 0 Set Menu=ViewUser
		IF %errorlevel% neq 0 GOTO ERROR
		SET INPUT=
		SET /P INPUT=Would you like to View another User (y/n)?
	
		IF /I '%INPUT%'=='y' goto ViewUser
		IF /I '%INPUT%'=='n' goto UserMenu

:AddUser
	CLS
	Net user
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
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

		IF %errorlevel% neq 0 Set Command="Add User"
		IF %errorlevel% neq 0 Set Menu=AddUser	
		IF %errorlevel% neq 0 GOTO ERROR
			echo !usr! was added.

		SET INPUT=
		SET /P INPUT=Would you like to Add another User (y/n)?
	
		IF /I '%INPUT%'=='y' goto AddUser
		IF /I '%INPUT%'=='n' goto UserMenu

:EnableUser
	Net user
	CLS
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% /active:yes

		IF %errorlevel% neq 0 Set Command="Enable User"
		IF %errorlevel% neq 0 Set Menu=EnableUser
		IF %errorlevel% neq 0 GOTO ERROR
			echo !usr! account was enabled.

		SET INPUT=
		SET /P INPUT=Would you like to Enable another User (y/n)?
	
		IF /I '%INPUT%'=='y' goto EnableUser
		IF /I '%INPUT%'=='n' goto UserMen

:DisableUser
	CLS
	net user
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% /active:no

		IF %errorlevel% neq 0 Set Command="Disable User"
		IF %errorlevel% neq 0 Set Menu=DisableUser
		IF %errorlevel% neq 0 GOTO ERROR
			echo !usr! account was disabled.

		SET INPUT=
		SET /P INPUT=Would you like to Disable another User (y/n)?
	
		IF /I '%INPUT%'=='y' goto DisableUser
		IF /I '%INPUT%'=='n' goto UserMenu

:Password
	Net user
	CLS
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
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

		echo Changing password for %usr%, and setting "change password at next login"
		net user %usr% %pwd% /EXPIRES:NEVER  /PASSWORDCHG:YES

		IF %errorlevel% neq 0 Set Command="User Password Reset"
		IF %errorlevel% neq 0 Set Menu=Password
		IF %errorlevel% neq 0 GOTO ERROR
			echo !usr! password was changed.

		SET INPUT=
		SET /P INPUT=Would you like to change the password of another User (y/n)?
	
		IF /I '%INPUT%'=='y' goto Password
		IF /I '%INPUT%'=='n' goto UserMenu

:AllPassword
	CLS
		Echo Creating User File
		IF NOT EXIST "%UserProfile%\Downloads\Data\NUL" mkdir "%UserProfile%\Downloads\Data"
		cd C:\Users
		dir /b /o:n /ad > %UserProfile%\Downloads\Data\users.txt
		cd %~dp0
		echo.

		echo  Type Below Requirements:
		echo.
		:password
			set /p pwd= Type Password:
			if [!pwd!]==[] goto password
		
		echo Changing password for all users, and setting "change password at next login"
		for /f %%i in ('type %UserProfile%\Downloads\Data\users.txt') do(
			if not %%i==Public (
			net user %%i %pwd% /EXPIRES:NEVER  /PASSWORDCHG:YES
			)
			)

		IF %errorlevel% neq 0 Set Command="User Password Reset"
		IF %errorlevel% neq 0 Set Menu=Password
		IF %errorlevel% neq 0 GOTO ERROR
		echo All Users Passwords changed to %pwd%
		pause

	Goto UserMenu

:GroupMenu
	CLS
		ECHO =====Tombstone Cyberpatriot=====
		ECHO ===========Instructor===========
		echo ==========Groups Menu===========
		echo.
		Net Localgroup
		echo.	
		echo Choose An option:
		echo 1. Add User to group
		echo 2. List Users of a group
		echo 3. Remove User from group
		echo Q. Back To User/Group Menu
		SET INPUT=
		SET /P INPUT=Please select a number:
	
		IF /I '%INPUT%'=='3' goto RemGroup
		IF /I '%INPUT%'=='2' goto ListGroupUsers
		IF /I '%INPUT%'=='1' goto AddGroup
		IF /I '%INPUT%'=='Q' goto UserGroupMenu
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the User
		echo Menu [1-3] or select 'Q' to User/Group Menu.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO GroupMenu

:RemGroup
	Net LocalGroup
	CLS
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% %usr% /delete 

		IF %errorlevel% neq 0 Set Command="Remove Group"
		IF %errorlevel% neq 0 Set Menu=RemGroup
		IF %errorlevel% neq 0 GOTO ERROR
			echo !grp! has been removed.

		SET INPUT=
		SET /P INPUT=Would you like to remove another group (y/n)?
	
		IF /I '%INPUT%'=='y' goto RemGroup
		IF /I '%INPUT%'=='n' goto GroupMenu

	Goto UserMenu

:ListUserGroup
	CLS
	Net LocalGroup
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% 

		IF %errorlevel% neq 0 Set Command="List User Group"
		IF %errorlevel% neq 0 Set Menu=ListUserGroup
		IF %errorlevel% neq 0 GOTO ERROR

		SET INPUT=
		SET /P INPUT=Would you like to list users of another group (y/n)?
	
		IF /I '%INPUT%'=='y' goto ListGroup
		IF /I '%INPUT%'=='n' goto GroupMenu

	Goto UserMenu

:AddGroup
	CLS
	Net LocalGroup
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% %usr% /add

		IF %errorlevel% neq 0 Set Command="Add Group"
		IF %errorlevel% neq 0 Set Menu=AddGroup
		IF %errorlevel% neq 0 GOTO ERROR
			echo !grp! has been added.

		SET INPUT=
		SET /P INPUT=Would you like to add another group (y/n)?
	
		IF /I '%INPUT%'=='y' goto AddGroup
		IF /I '%INPUT%'=='n' goto GroupMenu

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

:ListPrograms
	CLS
	wmic product get name
	echo.
	echo Please not the exact names of the programs you wish to uninstall.
		pause
		
	GoTo ProgramMenu

:RemProgram
	CLS
		setlocal EnableDelayedExpansion
		echo.
		echo  Type Below RequiREMents:
		echo.
		:program
			set /p prog= Type Program Name:
			if [!prog!]==[] goto program
		
		wmic product where name="%prog%" call uninstall

		IF %errorlevel% neq 0 Set Command="Remove Program" %prog%
		IF %errorlevel% neq 0 Set Menu=RemProgram
		IF %errorlevel% neq 0 GOTO ERROR
			echo !prog! has been removed.

		SET INPUT=
		SET /P INPUT=Would you like to remove another program (y/n)?
	
		IF /I '%INPUT%'=='y' goto RemProgram
		IF /I '%INPUT%'=='n' goto ProgramMenu

:RemUSBPCap
	CLS
	REM Uninstall USBPcap
		Echo Uninstall USBPcap exe
			"C:\Program Files\USBPcap\uninstall.exe" /S

		IF %errorlevel% neq 0 Set Command="Remove USBPCAP"
		IF %errorlevel% neq 0 Set Menu=RemUSBPCap
		IF %errorlevel% neq 0 GOTO ERROR
			echo USBPCap has been removed.

		Pause

	GOTO ProgramMenu

:RemNPCap
	CLS
	REM Uninstall NPCAP
		Echo Uninstall NPCAP exe
			"C:\Program Files\Npcap\uninstall.exe" /S


		IF %errorlevel% neq 0 Set Command="Remove NPCAP"
		IF %errorlevel% neq 0 Set Menu=RemNPCap
		IF %errorlevel% neq 0 GOTO ERROR
			echo NPCap has been removed.

		Pause

	GOTO ProgramMenu
	
:RemAngryip
	CLS
	REM Uninstall AngryIP
		Echo Uninstall AngryIP exe
			"C:\Program Files\Angry IP Scanner\uninstall.exe" /S

		IF %errorlevel% neq 0 Set Command="Remove Angry IP"
		IF %errorlevel% neq 0 Set Menu=RemAngryip
		IF %errorlevel% neq 0 GOTO ERROR
			echo Angry IP has been removed.

		Pause

	GOTO ProgramMenu


:RemTeamviewer
	CLS
	REM Uninstall TeamViewer
		Echo Uninstall TeamViewer exe
			"C:\Program Files (x86)\TeamViewer\uninstall.exe" /S

		IF %errorlevel% neq 0 Set Command="Remove TeamViewer"
		IF %errorlevel% neq 0 Set Menu=RemTeamViewer
		IF %errorlevel% neq 0 GOTO ERROR
			echo TeamViewer has been removed.

		Pause

	GOTO ProgramMenu
	
:RemWireshark
	CLS
	REM Uninstall WireShark
		Echo Uninstall WireShark exe version
			"C:\Program Files\Wireshark\uninstall.exe" /S
		Pause
		Echo Uninstall WireShark msi version
			MsiExec.exe /x{F8C728D8-D10A-4171-9DAF-01C0168D0233} /quiet

		IF %errorlevel% neq 0 Set Command="Remove WireShark"
		IF %errorlevel% neq 0 Set Menu=RemWireShark
		IF %errorlevel% neq 0 GOTO ERROR
			echo WireShark has been removed.

		Pause

	GOTO ProgramMenu

:RemFileZilla
	CLS
	REM Uninstall FileZilla
		Echo Uninstall FileZilla exe
			"C:\Program Files\FileZilla FTP Client\uninstall.exe" /S

		IF %errorlevel% neq 0 Set Command="Remove FileZilla"
		IF %errorlevel% neq 0 Set Menu=RemFileZilla
		IF %errorlevel% neq 0 GOTO ERROR
			echo FileZilla has been removed.

		Pause

	GOTO ProgramMenu

:Malwarebytes
	CLS
	REM Install Malwarebytes
		setlocal EnableDelayedExpansion
		echo  Type Below RequiREMents:
		echo.
		:directory
			set /p dir= Type directory to MBSetup.exe:
			if [!dir!]==[] goto directory

		%dir%\MBSetup.exe /SP- /SILENT /NOCANCEL

		IF %errorlevel% neq 0 Set Command="Install Malwarebytes"
		IF %errorlevel% neq 0 Set Menu=Malwarebytes
		IF %errorlevel% neq 0 GOTO ERROR
			echo MalwareBytes has been Installed.

		Pause

	GOTO ProgramMenu

:SecurityMenu
	CLS
		ECHO =======Tombstone Cyberpatriot=======
		ECHO =============Instructor=============
		ECHO ============Security Menu===========	
		echo Choose An option:
		echo 1. Import Hardened Security Policies
		echo 2. Import Original Security Policies
		echo 3. Turn off Auto Logon
		echo 4. Disable Remote Desktop
		echo 5. Set Windows Updates
		echo 6. Best Practices
		echo 7. Disable Weak services (Intensive)
		echo 8. Tools
		echo Q. Back To Main Menu

		SET INPUT=
		SET /P INPUT=Please select a number:
	
		If /I '%INPUT%'=='8' goto Tools
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

:BestPractice
	CLS
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
	
:Netplwiz
	CLS
	REM Turn off Autologon
		REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f
		echo Autologin turned off, please restart machine
	Pause
	
	GoTo SecurityMenu
				
:RDP
	CLS
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
	CLS	
	REM Windows auomatic updates
		reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
		net start wuauserc
		net start bits
		net start dosvc
	echo Automatic Updates Set
	pause
	
	GOTO SecurityMenu
				
:OriginalPolicies
	CLS
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
	CLS	
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
	CLS
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
:Tools
	CLS
		ECHO =======Tombstone Cyberpatriot=======
		ECHO =============Instructor=============
		ECHO =========Security Tools Menu========	
		echo Choose An option:
		echo 1. Integrity Scan
		echo 2. Possible Pentrations
		echo Q. Back To Security Menu

		SET INPUT=
		SET /P INPUT=Please select a number:
	
		IF /I '%INPUT%'=='2' goto PossiblePenetrations
		If /I '%INPUT%'=='1' goto IntegrityScan
		IF /I '%INPUT%'=='Q' goto SecurityMenu
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the Tool
		echo Menu [1-2] or select 'Q' to quit.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO SecurityMenu

:PossiblePenetrations
	CLS
	REM Listing possible penetrations
	IF NOT EXIST "%UserProfile%\Downloads\Data\NUL" mkdir "%UserProfile%\Downloads\Data"
	cd %UserProfile%\Downloads\Data
	echo "STARTING TO OUTPUT PROCESS FILES DIRECTLY TO THE DOWNLOADS\Data FOLDER!"
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
		
	GoTo ToolMenu
	
:IntegrityScan
	CLS
	REM START SYS INTEG SCAN!
		echo "STARTING SYSTEM INTERGRITY SCAN"
		echo "If it fails make sure you can access Sfc.exe"
		Sfc.exe /scannow
	Pause

	GOTO ToolMenu

:ERROR
	CLS
	ECHO The %Command% command didn't run successfully.
	echo Error Level: %errorlevel%
	Pause

	GOTO %Menu%

:Quit
	CLS

	ECHO ==============THANKYOU===============
	ECHO -------------------------------------
	ECHO ======PRESS ANY KEY TO CONTINUE======

	PAUSE>NUL
	EXIT
