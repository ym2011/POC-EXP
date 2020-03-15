import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
import struct

from threading import Thread
import Queue
import time
#version 0.01
def parse_ip_str(ip_str):
    '''Parses IP arguments for IPs, IP/CIDR and IP_Start/IP_End'''
   
    if "/" not in ip_str:
        ip = struct.unpack(">I", inet_aton(ip_str))[0]
        return (ip, ip)
    else:
        ip_base = ip_str[:ip_str.find("/")]
        ip_mask = ip_str[ip_str.find("/") + 1:]
        ip_base = struct.unpack(">I", inet_aton(ip_base))[0]
        if "." in ip_mask:
            ip_max = struct.unpack(">I", inet_aton(ip_mask))[0]
            return (ip_base, ip_max)
        else:
            cidr_mask = (2 ** (32 - int(ip_mask))) - 1
            return (ip_base & ~cidr_mask, ip_base | cidr_mask)

class ipv4_range:
    '''Iterator for getting a range of IPs'''
    def __init__(self, ip_str):
        self.ip_str = ip_str
        self.current, self.max = parse_ip_str(self.ip_str)    
    def __iter__(self):
        return self
    
    def next(self):
        if self.current <= self.max:
            rvalue = self.current
            self.current += 1
            rvalue = inet_ntoa(struct.pack(">I", rvalue))
            return rvalue
        else:
            raise StopIteration()

def gen_seq_ack(r0=None,delta = 0xC123D):
    '''Generates random tcp.seq/tcp.ack values for a given delta'''
    #If one value is supplied
    if r0 != None:
        rand_rt = random.randrange(0, 2)
        if r0 < delta or rand_rt == 1:
            return r0, r0 + delta
        else:
            return r0, r0 - delta

    r0 = random.randrange(delta, 0xffffffff)
    r1 = r0 - delta
        
    if random.randrange(0, 2) == 1:
        return r0, r1
    else:
        return r1, r0

def get_syn(src_ip, dst_ip, sport, dport, seq, ack, verbose = 0):
    '''Creates a SYN packet for scanning'''
    ip=IP(src=src_ip,dst=dst_ip)
    syn=TCP(sport=sport,dport=dport,flags='S',seq=seq, ack=ack)
    pkt = Ether()/ip/syn
    return pkt

def check_packet(pkt):
    if TCP in pkt:
        first_seq = pkt[TCP].ack - 1
        
        if pkt[TCP].sport != args.dport:
            return False, None
    
        if pkt[TCP].flags & 0x04:
            details = "%s:%d - TCP Reset" %(pkt[IP].src, pkt[TCP].sport)
            return (False, details)

        #validate SEQ/ACK delta
        if (pkt[TCP].flags & 0x12 and
            (first_seq - pkt[TCP].seq) != 0xC123D and 
            (pkt[TCP].seq - first_seq) != 0xC123D):
            details = "%s:%d - Incorrect SEQ/ACK delta seq: %08x ack: %08x" %\
                (pkt[IP].src, pkt[TCP].sport, pkt[TCP].seq, pkt[TCP].ack)
            return (False, details)
        #validate TCP options
        tcp_header = str(pkt[TCP])
        if tcp_header[-12:] != "\x02\x04\x05\xb4\x01\x01\x04\x02\x01\x03\x03\x05":
            details = "%s:%d - Incorrect TCP options: %s" %\
                (pkt[IP].src, pkt[TCP].sport, tcp_header.encode("hex"))
            return (False, details)
        
        details =  "%s:%d - Found implant seq: %08x ack: %08x" %\
            (pkt[IP].src, pkt[TCP].sport, pkt[TCP].seq, pkt[TCP].ack)
        return (True, details)
    return (False,None)

def sniff_add_packet(pkt):  
    '''Helper function for sniffer daemon thread'''
    global packet_queue, log
    packet_queue.put(pkt)
    result, details = check_packet(pkt)
    
    if result == False and details != None:
        log.debug(details)
        
    if result == True:
        log.info(details)

def sniff_daemon(iface, dport, stop_queue):
    '''Sniffer daemon thread that collects packets for later inspection'''
    global log
    
    try:
        r = sniff(iface=iface, 
            filter="tcp port %d or icmp" % dport, 
            prn = sniff_add_packet, 
            store = 0,
            stop_filter = lambda x: stop_queue.empty())
    except:
        log.error("Failed to sniff packets")
        
    log.debug("Sniffer thread exiting")

def scan_thread(iface, scan_queue):
    global log
    while True:
        try:
            pkt = scan_queue.get(block=False)
            log.debug("Sending Packet: %s sport: %d dport: %d seq: %08x ack: %08x" %\
                    (pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].seq, pkt[TCP].ack))
            sendp(pkt, iface=iface, verbose=0)
            scan_queue.task_done()
        except:
            break

parser = argparse.ArgumentParser(description='SYNfulKnock Scanner')
parser.add_argument("-s", "--src", action='store', help="SRC IP", default = None)
parser.add_argument("-d", "--dst", action='append', help="Target to be scanned (IP, IP/CIDR, First IP/Last IP)", default = [])
parser.add_argument("--sport", type=int, help="Source port", default = None)
parser.add_argument("--dport", type=int, help="Destination port", default = 80)
parser.add_argument("-v", "--verbose", action='store_true', help="verbose output", default = False)
parser.add_argument("--seq", action='store', help="TCP sequence number", default = None)
parser.add_argument("--ack", action='store', help="TCP acknowledgement number", default = None)
parser.add_argument("-t", "--threads", type=int, help="Max send threads", default = 10)

parser.add_argument("--rd", action='store', help="Filename to load sniffed packets", default = None)
parser.add_argument("--wr", action='store', help="Filename to save sniffed packets", default = None)
parser.add_argument("--iface", action='store', help="Interface to sniff and send packets", default = "eth0")
parser.add_argument("--log", action='store', help="Filename to save console log", default = None)

args = parser.parse_args()
conf.sniff_promisc = False

################################
#Configure logging
log = logging.getLogger('scanner')
log_format = logging.Formatter("%(asctime)s %(lineno)s %(levelname)-07s %(message)s")

sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(log_format)
log.addHandler(sh)
log.setLevel(logging.INFO)

if args.verbose == True:
   log.setLevel(logging.DEBUG)

if args.log != None:
    fh = logging.FileHandler(args.log)
    fh.setFormatter(log_format)
    log.addHandler(fh)
 
################################
#Run scan if not processing pcap
sniff_packets = []
if args.rd == None: 
    packet_queue = Queue.Queue()
    syn_queue = Queue.Queue()
    stop_queue = Queue.Queue()
    stop_queue.put(True)
    sniffer = Thread(name="Packet Sniffer", target=sniff_daemon, args=(args.iface, args.dport, stop_queue))
    sniffer.setDaemon(True)
    sniffer.start()
    log.info("Sniffer daemon started")

    syn_pkts = []
    try:
        for dst in args.dst:
            for scan_ip in ipv4_range(dst):
                dport = args.dport
                if args.seq == None and args.ack ==None:
                    seq, ack = gen_seq_ack()
                elif args.seq != None:
                    seq, ack = gen_seq_ack(args.seq)
                elif args.ack != None:
                    ack, seq = gen_seq_ack(args.ack)
                
                if args.sport == None:
                    sport = random.randint(1024, 65535)
                else:
                    sport = args.sport
                
                log.debug("Creating Packet: %s sport: %d dport: %d seq: %08x ack: %08x" %\
                    (scan_ip, sport, dport, seq, ack))
                
                pkt = get_syn(args.src, scan_ip, sport, dport, seq, ack)
                syn_queue.put(pkt)
                syn_pkts.append(pkt)
        
        log.info("Sending %d syn packets with %d threads" % (len(syn_pkts), args.threads))
        
        #Start scanning threads
        for x in range(args.threads):
            t = Thread(name="Scanner_%d" % x, target=scan_thread, args=(args.iface, syn_queue))
            t.start()
        #Wait for scanner threads to empty queue
        log.info("Waiting to complete send")

        #need a threadpool here
        t.join()
        
        #Sleep to let packets arrive
        time.sleep(10)
        
        if syn_queue.empty():
            log.info("All packets sent")
        else:
            log.error("Not all packets sent")

        #Empty queue to stop sniffer thread
        stop_queue.get()

        while True:
            try:
                pkt = packet_queue.get(block=False)
                sniff_packets.append(pkt)
            except Queue.Empty:
                break
    except:
        log.error("Error sending packets: " + str(sys.exc_info()[1]))
        log.error("Writing collected packets to error.pcap")
        wrpcap("error.pcap", sniff_packets)
else:
    sniff_packets = rdpcap(args.rd)

if len(sniff_packets) == 0:
    log.info("Failed to identify any packets, check permissions (sudo)")
    exit(0)

################################
#Log collected pcaps
if args.wr != None:
    log.info("Writing pcap log to %s" % args.wr)
    wrpcap(args.wr, sniff_packets)

################################
#Inspect collected packets 
#Print results in a concise location because debug is noisy
if args.verbose == True:
    for pkt in sniff_packets:
        result, reason = check_packet(pkt)
        
        if result == False and reason != None:
            log.debug(reason)
        if result == True:
            log.info(reason)

