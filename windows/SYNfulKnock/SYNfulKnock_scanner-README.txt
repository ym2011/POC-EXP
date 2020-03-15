Sends a crafted TCP SYN packet and analyses the SYN/ACK response for indications of an implant. The script relies on the Scapy packet manipulation library (http://www.secdev.org/projects/scapy/) for processing, sending and receiving packets. The scanning process uses several scan threads and a single thread for collecting the responses.  

Sample command line:
    sudo python ./SYNfulKnock_scanner.py -d 192.168.42.0/24 -t 5 --iface eth0 --wr log.pcap --log log.txt -v

The '-d' argument identifies the target network to scan. This can be a single IP, IP/CIDR or a range of IPs in the format [IP start]/[IP end]. Multiple '-d' arguments can be specified to scan more than one block or range at a single time. When scanning a CIDR or network range, the scanner will send a scan packet to the network and broadcast addresses because the implant responds to these addresses as well. The '-t' argument sets the number of send threads (no idea on performance issues when raising this, tested with 10). '--iface' is the interface to send and receive packets on. '-wr' writes the sniff results to a pcap file once scanning is completed. This pcap can be tested again by the scanner script using the command: python ./SYNfulKnock_scanner.py --rd log.pcap. The '--log' argument saves the console output to the file specified.

Sample execution (without verbose):

sudo  python ./SYNfulKnock_scanner.py -d 10.1.1.1/24 -t 5 --iface eth0 --wr log.pcap --log log.txt | more


Help output:

usage: SYNfulKnock_scanner.py [-h] [-s SRC] [-d DST] [--sport SPORT]
                                [--dport DPORT] [-v] [--seq SEQ] [--ack ACK]
                                [--threads THREADS] [--rd RD]
                                [--wr WR] [--iface IFACE] [--log LOG]

SYNfulKnock Scanner

optional arguments:
  -h, --help            show this help message and exit
  -s SRC, --src SRC     SRC IP
  -d DST, --dst DST     Target to be scanned (IP, IP/CIDR, First IP/Last IP)
  --sport SPORT         Source port
  --dport DPORT         Destination port
  -v, --verbose         verbose output
  --seq SEQ             TCP sequence number
  --ack ACK             TCP acknowledgement number
  -t, —-threads THREADS Max send threads
  --rd RD               Filename to load sniffed packets
  --wr WR               Filename to save sniffed packets
  --iface IFACE         Interface to sniff and send packets
  --log LOG             Filename to save console log