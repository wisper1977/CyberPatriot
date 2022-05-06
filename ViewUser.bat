@Echo off

:ViewUser
		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:username
			set /p usr= Type Username:
			if [!usr!]==[] goto username

		net user %usr% 
		pause
		goto ViewUser