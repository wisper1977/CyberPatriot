@Echo off

:RemGroup
	Net LocalGroups
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
	goto RemGroup