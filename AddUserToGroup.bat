@Echo off

:AddGroup
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

		net localgroup %grp% %usr% /add 
		pause
	goto AddGroup