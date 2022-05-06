@echo off

:UserMenu
	CLS
		echo ============Users Menu============
		echo.
		echo ============Users============
		Net User
		echo.
		echo ============Groups============
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
	GOTO UserMenu

:ViewUser
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% 
		pause

	Goto UserMenu

:RemGroup
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
		pause

	Goto UserMenu

:ListUserGroup
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% 
		pause

	Goto UserMenu

:EnableUser
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% /active:yes
		pause

	Goto UserMenu

:DisableUser

	net user
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% /active:no
		pause

	Goto UserMenu

:Password
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

		net user %usr% %pwd% /EXPIRES:NEVER  /PASSWORDCHG:YES 
		pause

	Goto UserMenu

:AddGroup
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
		pause

	Goto UserMenu

:AddUser

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
		pause

	Goto UserMenu
