	@echo off
	REM Turn off Autologon
		REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f
		echo Autologin turned off, please restart machine
	Pause