@echo off

:Updates	
	Rem Windows auomatic updates
		reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
	echo Automatic Updates Set
	pause