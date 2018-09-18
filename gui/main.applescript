-- Written by Doug Reed Copyright 2009
-- Released as Freeware.

on open argv
	try
		set tFile to argv -- or use an alias to any file
		set tPath to quoted form of (POSIX path of tFile) -- the shell's form. quoted form of is required if the path might include spaces.
		set tName to name of (info for tFile) -- standard AppleScript
		set my_extension to ""
		set _length to (count of tName)
		if _length > 4 then
			set my_extension to text ((the number of characters of tName) - 3) thru -1 of tName
		end if
		if my_extension = ".aes" or my_extension = ".AES" then
			set my_direction to "decryption"
		else
			set my_direction to "encryption"
		end if
		set my_pass to quoted form of text returned of (display dialog "Enter password for " & Â
			my_direction Â
				with title Â
			"AESCrypt" with icon 1 Â
			default answer Â
			"" buttons {"Continue"} Â
			default button 1 Â
			with hidden answer)
		
		set myPath to (path to me) as text
		set myAES to myPath & ":AESCrypt.app:Contents:MacOS:aescrypt"
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