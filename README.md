# AES Crypt for MacOS


This is a mac version of the AES Crypt software available at www.aescrypt.com.
The code for the command-line utility is the same source code used for Linux.


### Building and installing the command-line programs

Building the program from the source code, you probably will need the development tools of 
your MacOS installed (e.g. XCode).
In the 'src' directory, just type "make". If the command succeeds, you should have the 
executable files compiled in the directory.  To install them, you can type "make install" 
or manually copy the executable files wherever you want them. The two files of interest 
are "aescrypt" and "aescrypt_keygen".


### AESCrypt.app - a droplet GUI application for Mac

AESCrypt, which can be downloaded from www.aescrypt.com, is a small graphical droplet 
application for MacOS. It is based on a simple applescript invoking aescrypt. The script 
itself and other resources needed to build the package can be found in the 'gui' directory.

If you want to rebuild/repackage the App yourself, you can do it following the next 
steps:

1. Open main.applescript in ScriptEditor
2. From the Editor, export it with the name AESCrypt. For the file format choose 
'Application'. It will create an application bundle named AEScrypt.app in your folder. 
Practically, it is just a directory in the file system with a well-defined structure.
3. Right-clicking on your AESCrypt icon choose the 'Show Package Contents' command. 
Selecting this command displays a new Finder window set to the top level of the package 
directory. You can use this window to navigate the package's directory structure and make 
changes as if it were a regular directory.
4. Copy the two icon files ("droplet.icns", "lock.icns") to 'Contents/Resources'.
5. Copy the compiled utilities "aescrypt" and "aescrypt_keygen" (latter is optional) to 
'Contents/MacOS'.
6. The main applescript is already in the 'Contents/Resources/Scripts' directory in a 
compiled format.
7. Copy Info.plist (overwriting the original file) to 'Contents'.
8. You are ready. :) Move your freshly created application to any folder you want.
