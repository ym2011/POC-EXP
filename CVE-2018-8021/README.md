# Apache Superset pickle library code execution
IBM : Apache Superset could allow a remote attacker to execute arbitrary code on the system, caused by the use of unsafe load method from the pickle library to deserialize data. By sending specially-crafted request, an attacker could exploit this vulnerability to execute arbitrary code on the system.
# Refs : 
 - https://github.com/apache/incubator-superset/pull/4243
 - https://nvd.nist.gov/vuln/detail/CVE-2018-8021
 - https://exchange.xforce.ibmcloud.com/vulnerabilities/152702
 
# Usage : 

    usage: exploit.py [-h] -t TCP -tp TPORT -i IP -p PORT -U USER -P PASSW

    optional arguments:
      -h, --help            show this help message and exit
      -t TCP, --tcp TCP     tcp ip for shell
      -tp TPORT, --tport TPORT
                            tcp port for shell
      -i IP, --ip IP        ip
      -p PORT, --port PORT  port
      -U USER, --user USER  User belong to Superset 
      -P PASSW, --passw PASSW
                            password of the user !
                            
__Note  :  User and Pass Must belong to a user that can import Dashboards on Superset!!!__
# Creadits 
Please Note Original PoC has been written by _David May_ [david.may@semanticbits.com][https://github.com/DavidMay121] 
