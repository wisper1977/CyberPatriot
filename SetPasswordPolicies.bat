@echo off

:PasswordPolicies
		REM account password policy set
			echo New requirements are being set for your passwords
		net accounts /MINPWLEN:12 /MAXPWAGE:60 /MINPWAGE:5 /UNIQUEPW:3 /lockoutthreshold:5 /lockoutwindow:15 /lockoutduration:30
			echo New password policy:
			echo Minimum password length of 12 characters
			echo Maximum password age of 60
			echo Minimum password age of 5
			echo Unique password threshold set to 3 (default is 5)
			echo Lockout threshold 5 attempts
			echo Lockout Window 15 minutes
			echo Lockout Duration 30 minutes
		pause
			REM Delete system tasks
			schtasks /Delete /TN *
			pause
		net accounts
