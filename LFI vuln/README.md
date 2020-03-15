Panoptic
===

![Logo](http://i.imgur.com/PPGy8UE.jpg)

Panoptic is an open source penetration testing tool that automates the process of search and retrieval of content for common log and config files through path traversal vulnerability. Official introductionary post can be found [here](http://websec.ca/blog/view/panoptic). Also, you can find a sample run [here](https://gist.github.com/stamparm/5335273).

### Help Menu
    Usage: panoptic.py --url TARGET [options]

    Options:
      -h/--help             show this help message and exit
      -v/--verbose          display extra output information
      -u/--url=URL          set target URL
      -p/--param=PARAM      set parameter name to test for (e.g. "page")
      -d/--data=DATA        set data for HTTP POST request (e.g. "page=default")
      -t/--type=TYPE        set type of file to look for ("conf" or "log")
      -o/--os=OS            set filter name for OS (e.g. "*NIX")
      -s/--software=SOFT..  set filter name for software (e.g. "PHP")
      -c/--category=CATE..  set filter name for category (e.g. "FTP")
      -l/--list=GROUP       list available filters for group (e.g. "software")
      -a/--auto             avoid user interaction by using default options
      -w/--write-files      write content of retrieved files to output folder
      -x/--skip-parsing     skip special tests if *NIX passwd file is found
      --load=LISTFILE       load and try user provided list from a file
      --ignore-proxy        ignore system default HTTP proxy
      --proxy=PROXY         set proxy (e.g. "socks5://192.168.5.92")
      --user-agent=UA       set HTTP User-Agent header value
      --random-agent        choose random HTTP User-Agent header value
      --cookie=COOKIE       set HTTP Cookie header value (e.g. "sid=foobar")
      --header=HEADER       set a custom HTTP header (e.g. "Max-Forwards=10")
      --prefix=PREFIX       set prefix for file path (e.g. "../")
      --postfix=POSTFIX     set postfix for file path (e.g. "%00")
      --multiplier=MULTI..  set multiplication number for prefix (default: 1)
      --bad-string=STRING   set a string occurring when file is not found
      --replace-slash=RE..  set replacement for char / in paths (e.g. "/././")
      --threads=THREADS     set number of threads (default: 1)
      --update              update Panoptic from official repository

### Examples
    ./panoptic.py --url "http://localhost/include.php?file=test.txt"
    ./panoptic.py --url "http://localhost/include.php?file=test.txt&id=1" --param file
    ./panoptic.py --url "http://localhost/include.php" --data "file=test.txt&id=1" --param file
    
    ./panoptic.py --list software
    ./panoptic.py --list category
    ./panoptic.py --list os
    
    ./panoptic.py -u "http://localhost/include.php?file=test.txt" --os Windows
    ./panoptic.py -u "http://localhost/include.php?file=test.txt" --software WAMP

