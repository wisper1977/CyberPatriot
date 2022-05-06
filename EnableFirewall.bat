@echo off

:Firewall
	net start MpsSvc
	
	echo Enabling firewall (make sure group policy is allowing modifications to the firewall)
		netsh advfirewall set allprofiles state on
	echo Firewall enabled
	Pause