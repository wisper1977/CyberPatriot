@echo off

Title Tombstone Cyberpatriot Script

GOTO MainMenu

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
		echo 1. Users (Sub-Menu)		
		echo 2. Groups (Sub-Menu)
		echo Q. Back To Main Menu
		SET INPUT=
		SET /P INPUT=Please select a number:
	
		IF /I '%INPUT%'=='2' goto GroupMenu
		IF /I '%INPUT%'=='1' goto UserMenu
		IF /I '%INPUT%'=='Q' goto MainMenu
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the User
		echo Menu [1-2] or select 'Q' to go to Main Menu.
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
		echo Menu [1-6] or select 'Q' to go to User/Group Menu.
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

:AdminGuest
	CLS
		SET INPUT=
		SET /P INPUT=Would you like to Disable the Administrator and Guest Accounts (y/n)?
	
		IF /I '%INPUT%'=='y' goto DisableAdminGuest
		IF /I '%INPUT%'=='n' goto UserMenu
	
		:DisableAdminGuest
			echo Disabling Administrator and Guest User
			net user administrator /active:no
			net user Guest /active:no
			echo Administrator and Guest User Disabled
	pause
	goto UserMenu

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
		echo 4. Add Group
		echo 5. Remove Group
		echo Q. Back To User/Group Menu
		SET INPUT=
		SET /P INPUT=Please select a number:

		IF /I '%INPUT%'=='5' goto RemGroup
		IF /I '%INPUT%'=='4' goto AddGroup	
		IF /I '%INPUT%'=='3' goto RemUserGroup
		IF /I '%INPUT%'=='2' goto ListGroupUsers
		IF /I '%INPUT%'=='1' goto AddUserGroup
		IF /I '%INPUT%'=='Q' goto UserGroupMenu
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the User
		echo Menu [1-3] or select 'Q' to go to User/Group Menu.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO GroupMenu

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
	
		IF /I '%INPUT%'=='y' goto ListUserGroup
		IF /I '%INPUT%'=='n' goto GroupMenu

:AddGroup
	CLS
	Net LocalGroup
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% /add 

		IF %errorlevel% neq 0 Set Command="Add Group"
		IF %errorlevel% neq 0 Set Menu=AddGroup
		IF %errorlevel% neq 0 GOTO ERROR
			echo !grp! has been removed.

		SET INPUT=
		SET /P INPUT=Would you like to add another group (y/n)?
	
		IF /I '%INPUT%'=='y' goto AddGroup
		IF /I '%INPUT%'=='n' goto GroupMenu

:RemGroup
	CLS
	Net LocalGroup
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% /delete 

		IF %errorlevel% neq 0 Set Command="Remove Group"
		IF %errorlevel% neq 0 Set Menu=RemGroup
		IF %errorlevel% neq 0 GOTO ERROR
			echo !grp! has been removed.

		SET INPUT=
		SET /P INPUT=Would you like to remove another group (y/n)?
	
		IF /I '%INPUT%'=='y' goto RemGroup
		IF /I '%INPUT%'=='n' goto GroupMenu

:RemUserGroup
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

		net localgroup %grp% %usr% /delete 

		IF %errorlevel% neq 0 Set Command="Remove User Group"
		IF %errorlevel% neq 0 Set Menu=RemUserGroup
		IF %errorlevel% neq 0 GOTO ERROR
			echo !usr! has been removed from !grp!.

		SET INPUT=
		SET /P INPUT=Would you like to remove another user from a group (y/n)?
	
		IF /I '%INPUT%'=='y' goto RemUserGroup
		IF /I '%INPUT%'=='n' goto GroupMenu

:AddUserGroup
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

		IF %errorlevel% neq 0 Set Command="Add User Group"
		IF %errorlevel% neq 0 Set Menu=AddUserGroup
		IF %errorlevel% neq 0 GOTO ERROR
			echo !usr! has been added to !grp!.

		SET INPUT=
		SET /P INPUT=Would you like to add another user to a group (y/n)?
	
		IF /I '%INPUT%'=='y' goto AddUserGroup
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
		echo Menu [1-9] or select 'Q' to go to MainMenu.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
			
	PAUSE > NUL
	GOTO ProgramMENU

:ListPrograms
	CLS
	wmic product get name
	echo.
	echo Please note the exact names of the programs you wish to uninstall.
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
		echo 1. Policies (Sub-Menu)
		echo 2. Turn off Auto Logon
		echo 3. Disable Remote Desktop
		echo 4. Set Windows Updates
		echo 5. Set Network Settings
		echo 6. Check Windows Features
		echo 7. Enable Firewall and Set Rules
		echo 8. Turn UAC to Max
		echo 9. Tools (Sub-Menu)
		echo Q. Back To Main Menu

		SET INPUT=
		SET /P INPUT=Please select a number:
	
		If /I '%INPUT%'=='9' goto ToolsMenu
		If /I '%INPUT%'=='8' goto UAC
		IF /I '%INPUT%'=='7' goto Firewall
		IF /I '%INPUT%'=='6' goto CheckWindowsFeatures
		IF /I '%INPUT%'=='5' goto BestPractice
		IF /I '%INPUT%'=='4' goto Updates
		IF /I '%INPUT%'=='3' goto RDP
		IF /I '%INPUT%'=='2' goto Netplwiz
		IF /I '%INPUT%'=='1' goto PoliciesMenu
		IF /I '%INPUT%'=='Q' goto MainMenu
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the Security
		echo Menu [1-9] or select 'Q' to go to MainMenu.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO SecurityMENU

:UAC
	CLS
		echo Turning UAC to max
		reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
		echo UAC turned to max
	pause
	
	goto SecurityMenu

:Netplwiz
	CLS
		echo Turn off Autologon
		echo.
		REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f
		echo Autologin turned off, please restart machine
	Pause
	
	GoTo SecurityMenu

:RDP
	CLS
		echo Turning off RDP
		reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
		REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\REMote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
		reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

		REM Failsafe
		if %errorlevel%==1 netsh advfirewall firewall set service type = Remotedesktop mode = disable
		
		echo Remote Assistance And Remote Desktop are disabled
	pause

	GOTO SecurityMenu

:Updates
	CLS	
		echo Windows auomatic updates
		reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
		net start wuauserc
		net start bits
		net start dosvc
		echo Automatic Updates Set
	pause
	
	GOTO SecurityMenu

:CheckWindowsFeatures
	CLS
		echo Checking Windows Features
		echo.

		echo Disabling Telnet Client\Server
		dism /online /disable-feature /featurename:TelnetClient
		dism /online /disable-feature /featurename:TelnetServer
		echo Telnet Client\Server Disabled
		echo.

		echo Disabling SNMP
		dism /online /disable-feature /featurename:SNMP-SC
		echo SNMP Disabled
		echo.

		echo Disabling RIP Listener
		dism /online /disable-feature /featurename:RipListener
		echo RIP Listner Disabled
		echo.

		echo Disabling Client for NFS
		dism /online /disable-feature /featurename:ClientForNFS-Infrastructure
		echo Telnet Client for NFS Disabled
		echo.

		echo Disabling Internet Information Services (IIS)
		dism /online /disable-feature /featurename:IIS-WebServer
		dism /online /disable-feature /featurename:IIS-WebServerRole
		dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
		dism /online /disable-feature /featurename:IIS-DefaultDocument
		dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
		dism /online /disable-feature /featurename:IIS-HttpErrors
		dism /online /disable-feature /featurename:IIS-HttpRedirect
		dism /online /disable-feature /featurename:IIS-StaticContent
		dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
		dism /online /disable-feature /featurename:IIS-HttpLogging
		dism /online /disable-feature /featurename:IIS-LoggingLibraries
		dism /online /disable-feature /featurename:IIS-RequestMonitor
		dism /online /disable-feature /featurename:IIS-HttpTracing
		dism /online /disable-feature /featurename:IIS-CustomLogging
		dism /online /disable-feature /featurename:IIS-ODBCLogging
		dism /online /disable-feature /featurename:IIS-Security
		dism /online /disable-feature /featurename:IIS-BasicAuthentication
		dism /online /disable-feature /featurename:IIS-WindowsAuthentication
		dism /online /disable-feature /featurename:IIS-DigestAuthentication
		dism /online /disable-feature /featurename:IIS-ClientCertificateMappingAuthentication
		dism /online /disable-feature /featurename:IIS-IISCertificateMappingAuthentication
		dism /online /disable-feature /featurename:IIS-URLAuthorization
		dism /online /disable-feature /featurename:IIS-RequestFiltering
		dism /online /disable-feature /featurename:IIS-IPSecurity
		dism /online /disable-feature /featurename:IIS-Performance
		dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
		dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
		dism /online /disable-feature /featurename:IIS-WebServerManagementTools
		dism /online /disable-feature /featurename:IIS-ManagementConsole
		dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
		dism /online /disable-feature /featurename:IIS-ManagementService
		dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
		echo Internet Information Services (IIS) Disabled
		echo.

	pause
	goto SecurityMenu

:Firewall
	CLS
		echo Enabling firewall
		netsh advfirewall set allprofiles state on
		echo Firewall Enabled
		echo.

		echo Inbound=disable MS Edge
		netsh advfirewall firewall add rule name="Block MS Edge" dir=in action=block program="%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
		echo MS Edge Disabled
		echo.

		echo Inbound=disable Search
		netsh advfirewall firewall add rule name="Block Search" dir=in action=block program="%ProgramFiles(x86)%\Windows Kits\10\Windows Performance Toolkit\SearchUI.exe"
		echo Search Disabled
		echo.

		echo Inbound=disable MSN Money
		netsh advfirewall firewall add rule name="Block MSN Money" dir=in action=block program="%ProgramFiles(x86)%\Windows Live\Finance\Finance.exe"
		echo MSN Money Disabled
		echo.

		echo Inbound=disable MSN Sports
		netsh advfirewall firewall add rule name="Block MSN Sports" dir=in action=block program="%ProgramFiles(x86)%\Windows Live\Sports\Sports.exe"
		echo MSN Sports Disabled
		echo.

		echo Inbound=disable MSN News
		netsh advfirewall firewall add rule name="Block MSN News" dir=in action=block program="%ProgramFiles(x86)%\Windows Live\News\News.exe"
		echo MSN News Disabled
		echo.

		echo Disable port 1900 UPnP
		reg add "HKLM\Software\Microsoft\DirectplayNATHelp\DPNHUPnP" /v "UPnPMode" /t REG_DWORD /d 2 /f
		echo port 1900 UPnP Disabled
		echo.

	pause

	goto SecurityMenu

:Network
	CLS
		rem Disable Client for MS Networks
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v "TransportBindName" /t REG_SZ /d " " /f

		rem Disable File and Printer Sharing for Microsoft Networks
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d 0 /f

		rem Disable QoS
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\QoS" /v "Start" /t REG_DWORD /d 4 /f

		rem Disable Microsoft Network Adapter Multiplexor Protocol
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netman" /v "Start" /t REG_DWORD /d 4 /f

		rem Disable Microsoft LLDP Protocol Driver
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\lltdio" /v "Start" /t REG_DWORD /d 4 /f

		rem Disable Link Layer Topology Discovery Mapper IO Driver
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /v "Start" /t REG_DWORD /d 4 /f

		rem Disable Link Layer Topology Discovery Responder
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6" /v "DisabledComponents" /t REG_DWORD /d 0xffffffff /f

		rem Disable Internet Protocol version 6
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6" /v "Start" /t REG_DWORD /d 4 /f

		rem 'WINS' tab, select 'Disable NETBIOS over TCP/IP'
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v "TransportBindName" /t REG_SZ /d " " /f

		rem Use SmartScreen online services: ON
		reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 1 /f

		rem Automatically connect to suggested open hotspots: OFF
		reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f

		rem Automatically connect to hotspots temporarily to see if paid network services are available: OFF
		reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowed" /t REG_DWORD /d 0 /f

		echo Network settings changed
		echo.
	pause

	goto SecurityMenu

:PoliciesMenu
	CLS
		ECHO =======Tombstone Cyberpatriot=======
		ECHO =============Instructor=============
		ECHO =========Security Policies Menu========	
		echo Choose An option:
		echo 1. Export Local Security Policies
		echo 2. Import Original Policies
		echo 3. Import Hardened Policies
		echo 4. Set Password Policies
		echo 5. Set Lockout Policies
		echo 6. Set Audit Policies
		echo 7. Set Security Options
		echo Q. Back To Security Menu

		SET INPUT=
		SET /P INPUT=Please select a number:

		IF /I '%INPUT%'=='6' goto secOpt
		IF /I '%INPUT%'=='6' goto audit
		IF /I '%INPUT%'=='5' goto lockout
		IF /I '%INPUT%'=='4' goto passwdPol
		If /I '%INPUT%'=='3' goto HardenedPolicies
		IF /I '%INPUT%'=='2' goto OriginalPolicies
		If /I '%INPUT%'=='1' goto ExportPolicies
		IF /I '%INPUT%'=='Q' goto Quit
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the Tool
		echo Menu [1-2] or select 'Q' to go to Security Menu.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO SecurityMen

:ExportPolicies
	CLS
	REM Secuirty Policies
	IF NOT EXIST "%UserProfile%\Downloads\Data\NUL" mkdir "%UserProfile%\Downloads\Data"
	
	setlocal EnableDelayedExpansion
		echo  Exporting Security Policies to Downloads Folder
		echo.
		
		secedit.exe /export /cfg %UserProfile%\Downloads\Data\originalsecpol.inf

		echo Security Policies exported to Downloads Folder
		echo.
	pause

	GOTO PoliciesMenu

:OriginalPolicies
	CLS
	REM Secuirty Policies
		setlocal EnableDelayedExpansion
		echo  Make sure Original Settings are in Downloads folder.
		echo.
	
		secedit /configure /db %temp%\temp.sdb /cfg %UserProfile%\Downloads\Data\originalsecpol.inf
		echo Original Settings Imported from Downloads
		echo.
	pause

	GOTO PoliciesMenu

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

	GOTO PoliciesMenu

:passwdPol
	CLS
		rem Sets the password policy
		rem Set complexity requirments
		echo Setting pasword policies
		net accounts /minpwlen:8
		net accounts /maxpwage:60
		net accounts /minpwage:10
		net accounts /uniquepw:3
		echo.
		echo Password Policies set
	pause
	goto PoliciesMenu
	
:lockout
	CLS
		rem Sets the lockout policy
		echo Setting the lockout policy
		net accounts /lockoutduration:30
		net accounts /lockoutthreshold:3
		net accounts /lockoutwindow:30
		echo.
		echo Account Lockout Policies set
	pause
	goto PoliciesMenu

:audit
	CLS
		echo Auditing the maching now
		auditpol /set /category:* /success:enable
		auditpol /set /category:* /failure:enable
		echo.
		echo Audit Policies set
	pause
	goto PoliciesMenu

:secOpt
	CLS
		echo Changing security options now.

		rem Restrict CD ROM drive
		reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

		rem Automatic Admin logon
		reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
	
		rem Logon message text
		set /p body=Please enter logon text: 
			reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticetext" /v LegalNoticeText /t REG_SZ /d "%body%"
	
		rem Logon message title bar
		set /p subject=Please enter the title of the message: 
			reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticecaption" /v LegalNoticeCaption /t REG_SZ /d "%subject%"
	
		rem Wipe page file from shutdown
		reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
	
		rem Disallow remote access to floppie disks
		reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
	
		rem Prevent print driver installs 
		reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
	
		rem Limit local account use of blank passwords to console
		reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
	
		rem Auditing access of Global System Objects
		reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
	
		rem Auditing Backup and Restore
		reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
	
		rem Do not display last user on logon
		reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
	
		rem UAC setting (Prompt on Secure Desktop)
		reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
	
		rem Enable Installer Detection
		reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
	
		rem Undock without logon
		reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
	
		rem Maximum Machine Password Age
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
	
		rem Disable machine account password changes
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
	
		rem Require Strong Session Key
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
	
		rem Require Sign/Seal
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
	
		rem Sign Channel
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
	
		rem Seal Channel
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
	
		rem Don't disable CTRL+ALT+DEL even though it serves no purpose
		reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f 
	
		rem Restrict Anonymous Enumeration #1
		reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
	
		rem Restrict Anonymous Enumeration #2
		reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
	
		rem Idle Time Limit - 45 mins
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f 
	
		rem Require Security Signature - Disabled pursuant to checklist
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f 
	
		rem Enable Security Signature - Disabled pursuant to checklist
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f 
	
		rem Disable Domain Credential Storage
		reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
	
		rem Don't Give Anons Everyone Permissions
		reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
	
		rem SMB Passwords unencrypted to third party
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
	
		rem Null Session Pipes Cleared
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
	
		rem remotely accessible registry paths cleared
		reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
	
		rem remotely accessible registry paths and sub-paths cleared
		reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
	
		rem Restict anonymous access to named pipes and shares
		reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
	
		rem Allow to use Machine ID for NTLM
		reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

		rem Enables DEP
		bcdedit.exe /set {current} nx AlwaysOn

		echo.
		echo Security Options Changed.

	pause
	goto PoliciesMenu

:ToolsMenu
	CLS
		ECHO =======Tombstone Cyberpatriot=======
		ECHO =============Instructor=============
		ECHO =========Security Tools Menu========	
		echo Choose An option:
		echo 1. Integrity Scan
		echo 2. Possible Pentrations
		echo 3. Remove Disallowed Media Files
		echo Q. Back To Security Menu

		SET INPUT=
		SET /P INPUT=Please select a number:

		IF /I '%INPUT%'=='3' goto DisallowedMediaFiles
		IF /I '%INPUT%'=='2' goto PossiblePenetrations
		If /I '%INPUT%'=='1' goto IntegrityScan
		IF /I '%INPUT%'=='Q' goto SecurityMenu
	
	CLS
	
		echo ============INVALID INPUT============
		echo -------------------------------------
		echo Please select a number from the Tool
		echo Menu [1-2] or select 'Q' to goto Security Menu.
		echo -------------------------------------
		echo ======PRESS ANY KEY TO CONTINUE======
	
	PAUSE > NUL
	GOTO SecurityMenu

:PossiblePenetrations
	CLS
	REM Listing possible penetrations
	IF NOT EXIST "%UserProfile%\Downloads\Data\NUL" mkdir "%UserProfile%\Downloads\Data"

	echo "STARTING TO OUTPUT PROCESS FILES DIRECTLY TO THE DOWNLOADS\Data FOLDER!"
		wmic process list brief > %UserProfile%\Downloads\Data\BriefProcesses.txt
		if %errorlevel%==1 echo Brief Processes failed to write

		wmic process list full > %UserProfile%\Downloads\Data\FullProcesses.txt
		if %errorlevel%==1 echo Full Processes failed to write

		wmic startup list full > %UserProfile%\Downloads\Data\StartupLists.txt
		if %errorlevel%==1 echo Startup Processes failed to write

		net start > %UserProfile%\Downloads\Data\StartedProcesses.txt
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

:DisallowedMediaFiles

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
