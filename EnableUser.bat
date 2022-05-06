@Echo off

:EnableUser
	net user
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% /active:yes
		pause
		goto EnableUser