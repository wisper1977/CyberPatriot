@Echo off

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

goto AddUser