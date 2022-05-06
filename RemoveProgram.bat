@echo off

		setlocal EnableDelayedExpansion
		echo  Type Below Requirements:
		echo.
		:program
			set /p prog= Type Program Name:
			if [!prog!]==[] goto program
		
		wmic product where name="%prog%" call uninstall 
		pause