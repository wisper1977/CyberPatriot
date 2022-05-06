@echo off

		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:group
			set /p grp= Type Group:
			if [!grp!]==[] goto group			

		net localgroup %grp% 
		pause