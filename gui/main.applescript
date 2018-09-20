-- Written by Doug Reed Copyright 2009
-- Released as Freeware.
-- Updated by Zoltan Kota, 2018

on open argv
	try
		set tFile to argv -- or use an alias to any file
		set tPath to quoted form of (POSIX path of tFile) -- the shell's form. quoted form of is required if the path might include spaces.
		set tName to name of (info for tFile) -- standard AppleScript
		set tExtension to name extension of (info for tFile)
		set status to true as boolean
		if tExtension = "aes" or tExtension = "AES" then
			set my_direction to "decryption"
			set dFile to (tFile as text)
			set _length to (count of dFile) - (count of tExtension) - 1
			set dFile to text 1 thru _length of dFile
			set status to FileExists(dFile)
		else
			set my_direction to "encryption"
			set dFile to (tFile as text) & ".aes"
			set status to FileExists(dFile)
		end if
		
		set my_pass to quoted form of text returned of (display dialog Â
			"Enter password for " & my_direction Â
			with title Â
			"AESCrypt" with icon 1 Â
			default answer Â
			"" buttons {"Continue"} Â
			default button (1) Â
			with hidden answer)
		
		set myPath to (path to me) as text
		set myAES to myPath & "Contents:MacOS:aescrypt"
		set myAES to quoted form of (POSIX path of myAES)
		
		if my_direction = "encryption" then
			do shell script (myAES & " -e -p " & my_pass & " " & tPath)
		else
			do shell script (myAES & " -d -p " & my_pass & " " & tPath)
		end if
		
	on error errStr number errorNumber
		error errStr number errorNumber
		display dialog "Error: " & errorNumber & " Text: " & errStr
	end try
end open

on FileExists(theFile)
	tell application "Finder"
		if exists theFile then
			display alert Â
				"WARNING!" message "Destination file '" & theFile & Â
				"' exists. Overwrite?" as warning Â
				buttons {"No", "Yes"} Â
				default button (2) Â
				cancel button (1)
		end if
	end tell
	return false
end FileExists
