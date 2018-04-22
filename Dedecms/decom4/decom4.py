#!/usr/bin/env python

##########################################################################################################
#
#   name: decom4.py
#   author: Greg Scott (@mwrlabs)
#   version: 1.0 (4/12/2013)
#   
#   description: automate the extraction of SAP DIAG and RFC credentials from packet capture.
#
#   ref: http://mwrlabs.infosecurity.com
#
#   Usage: decom4.py -f file.pcap
#
# Copyright (c) 2013, MWR InfoSecurity
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the MWR InfoSecurity nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
# OF THE POSSIBILITY OF SUCH DAMAGE.
#
####

import sys
import dpkt
import os
import array
import textwrap
import subprocess
import binascii
import sapgui
import getopt
import socket

#import saprfc

#take arguments
tcp_counter=0
rfc_counter=0
gui_counter=0
header=0
search="1f9d"
DPHeaderStart="ffffffff"
verbose=False
verboseFile = ""
creds_file = ""

#print header
print '''
==========================================================================================================
                        _       _         
                       | |     | |        
 _ __ _____      ___ __| | __ _| |__  ___ 
| '_ ` _ \ \ /\ / / '__| |/ _` | '_ \/ __|
| | | | | \ V  V /| |  | | (_| | |_) \__ \\
|_| |_| |_|\_/\_/ |_|  |_|\__,_|_.__/|___/

decom4.py by @mwrlabs

example: $ python decom4.py -f file.pcap -o creds.txt

==========================================================================================================
'''

try:
	opts, args = getopt.getopt(sys.argv[1:], "f:o:v", ["file=", "output=", "verbose"])
except getopt.GetoptError:
	sys.exit(2)
for opt, arg in opts:
	if opt in ("-f", "--file"):
		fi=open(arg)
		print "[+] Processing %s " % arg
	elif opt in ("-o", "--output"):
		creds_file = arg
		print "[+] Outputting creds to %s " % arg
	elif opt in ("-v", "--verbose"):
		verbose=True
try:
	pcap=dpkt.pcap.Reader(fi)
except Exception:
	print "[-] Filetype not recognised or bad options, .pcap only. pcapng is unsupported"
	exit()

def stripPacket(src_ip_addr_str, dst_ip_addr_str, hexStream):
	checkDP = hexStream[112:120]
	if checkDP == DPHeaderStart:
		global header
		header = header + 1
	# check if it's compressed (crude)
	if search in hexStream:
		# if it's compressed send it for parsing
		decomped, source = decompress(hexStream)
		#s end for dissection provided something came back
		if decomped != "":
			sapgui.reverse(src_ip_addr_str, dst_ip_addr_str, decomped, source, verbose, creds_file)

def decompress(stream):
	# break string at magic number and strip out useless info
	index = stream.rfind(search)
	packetSource = stream[24:32]
	stripFront = stream[(index-34):]
	# dump useful info in a temp file
	debugfile = open("debug.txt", 'wb')
	try:
		output2 = binascii.unhexlify("".join(stripFront.strip().split(" ")))
		debugfile.write(output2)
		debugfile.close()
		# summon the decompressor!
		subprocess.call(["./SAP_pkt_decompr", "debug.txt", "output.txt"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		outfile = open("output.txt", "rb")
		decomdata = outfile.read()
		# return the decompressed packet
		return decomdata, packetSource
	except Exception:
		return "", 0
		pass

if __name__ == '__main__':
	try:
		for ts, buf in pcap:
			ethernet = dpkt.ethernet.Ethernet(buf)
			ip = ethernet.data
			# check for TCP packets
			if ethernet.type == 2048 and ip.p == 6:
					tcp = ip.data
					tcp_counter += 1
					# check for sap GUI ports
					if tcp.dport >= 3200 and tcp.dport < 3300:
						b = bytes(ip)
						hexer = b.encode("hex")
						# send packet for processing
						gui_counter = gui_counter + 1
						src_ip_addr_str = socket.inet_ntoa(ip.src)
						dst_ip_addr_str = socket.inet_ntoa(ip.dst)
						stripPacket(src_ip_addr_str, dst_ip_addr_str, hexer)
					# check for SAP RFC ports
					elif tcp.dport >= 3300 and tcp.dport < 3400:
						b = bytes(ip)
						hexer = b.encode("hex")
						# send packet for processing
						rfc_counter = rfc_counter + 1
						#saprfc.rfc(hexer)
		# if linux cooked packet
		if tcp_counter==0:
			for ts, buf in pcap:
				data = buf[2:]
				ethernet=dpkt.ethernet.Ethernet(data)
				ip = ethernet.data
				# check for TCP packets
				if ethernet.type == 2048 and ip.p == 6:
						tcp = ip.data
						tcp_counter += 1
						if tcp.dport >= 3200 and tcp.dport < 3300:
							b = bytes(ip)
							hexer = b.encode("hex")
							gui_counter = gui_counter+1
							# send packet for processing
							src_ip_addr_str = socket.inet_ntoa(ip.src)
							dst_ip_addr_str = socket.inet_ntoa(ip.dst)
							stripPacket(src_ip_addr_str, dst_ip_addr_str, hexer)
						elif tcp.dport >= 3300 and tcp.dport < 3400:
							b = bytes(ip)
							hexer = b.encode("hex")
							rfc_counter = rfc_counter + 1
							#send packet for processing
							#saprfc.rfc(hexer)
							
	except Exception:
		pass

if os.path.isfile("debug.txt"):
	os.remove("debug.txt")
if os.path.isfile("output.txt"):
	os.remove("output.txt")
if os.path.isfile("tmp.txt"):
	os.remove("tmp.txt")
print "[+] TCP packets: %s" %(tcp_counter)
if header > 0:
	print "[+] %s DP Header Packets found - credentials likely!" % header
else:
	print "[-] No DP Header Packets found - credentials unlikely"
print "[+] SAP GUI Packets %s" % gui_counter
print "[+] SAP RFC Packets %s" % rfc_counter
print ""