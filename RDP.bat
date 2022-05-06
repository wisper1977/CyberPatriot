@echo off
	Rem Turns off RDP
		reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
		REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
		reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

	Rem Failsafe
		if %errorlevel%==1 netsh advfirewall firewall set service type = remotedesktop mode = disable
		
	echo Remote Assistance And Remote Desktop are disabled
		
	Pause