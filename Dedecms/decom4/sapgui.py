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

outputFile = open("tmp.txt", "wb")
credentialsFile = ""
verbose_file = "verbose.txt"
verboseFile = ""
counter = 0
gui = 0

def getCredsEField1(src_ip_addr_str, dst_ip_addr_str, appl4pack, code, source, verbose):
	totalAtoms = 0
	initialVal = 0
	maxim = 0
	counter = 0
	# takes atom length off the appropriate length bytes
	totalL = (ord(appl4pack[3])*16) + ord(appl4pack[4])
	# sets up the atom for dissection, and converts ip to readable address
	atoms = appl4pack[5:]
	octets = [source[i:i+2] for i in range(0, len(source), 2)]
	ip = [int(i, 16) for i in octets]
	ip_formatted = '.'.join(str(i) for i in ip)
	# another beast
	if ord(atoms[12]) < 127:
		while totalAtoms < (totalL+1) and maxim < 10:
			# take atom field length
			atomL = (ord(atoms[0])*16) + ord(atoms[1])
			totalAtoms = totalAtoms + atomL
			# get length of field
			fieldL = ord(atoms[14])
			# check for reasonable length of field
			if fieldL > 0:
				if counter == 0:
					#credentialsFile.write("##### APPL Atom element, EField1 found from %s! #####\n\r" % ip_formatted)
					credentialsFile.write("\r\n" + "[+] " + src_ip_addr_str + " --> " + dst_ip_addr_str + "\r\n\r\n")	
					# rip and write creds
				creds = atoms[(atomL-fieldL):atomL]
				credentialsFile.write(creds + "\n\r")
				counter = counter + 1
				# gear up for the next atom if there is one
				initialVal = atomL
				try:
					atomL = ord(atoms[atomL]) * 16 + ord(atoms[(atomL+1)])
				except Exception:
					atomL = 100000
				atoms = atoms[initialVal:]
				# maxim is here because encrypted traffic has caused major crashes here,
				# also, this ensures that the while loop does eventually end
			totalAtoms = totalAtoms + atomL 
			maxim = maxim + 1

	if verbose == True:
		totalAtoms = 0
		initialVal = 0
		maxim = 0
		counter = 0
		atoms = appl4pack[5:]
		while totalAtoms < (totalL + 1) and maxim < 10:
			# take atom field length
			atomL = (ord(atoms[0])*16) + ord(atoms[1])
			# get length of field
			fieldL = ord(atoms[14])
			# check for reasonable length of field
			if fieldL > 0:
				if counter == 0:
					#verboseFile.write("##### APPL Atom element, EField1 found from %s! #####\n\r" % ip_formatted)
					verboseFile.write("\r\n" + "[+] " + src_ip_addr_str + " --> " + dst_ip_addr_str + "\r\n\r\n")		
					# rip and write creds
				creds = atoms[(atomL-fieldL):atomL]
				verboseFile.write(creds + "\n\r")
				counter = counter + 1
				# gear up for the next atom if there is one
				initialVal = atomL
				try:
					atomL = ord(atoms[atomL]) * 16 + ord(atoms[(atomL+1)])
				except Exception:
					atomL = 100000
				atoms = atoms[initialVal:]
				# maxim is here because encrypted traffic has caused major crashes here,
				# also, this ensures that the while loop does eventually end 
			maxim = maxim + 1
			totalAtoms = totalAtoms + atomL

def getCredsEField2(src_ip_addr_str, dst_ip_addr_str, appl4pack, code, source, verbose):
	# set up for atom dissection
	maxim = 0
	counter = 0
	if code == 18:
		# if APPL4 get length and convert ip address to readable address
		# also, gear up for the big nonsense field ripper
		totalL = len(appl4pack) - 7
		atoms = appl4pack[7:]
		totalAtoms = 0
		initialVal = 0
		octets = [source[i:i+2] for i in range(0, len(source), 2)]
		ip = [int(i, 16) for i in octets]
		ip_formatted = '.'.join(str(i) for i in ip)
		if ord(atoms[12]) < 127:
			while totalAtoms < (totalL+1) and maxim < 10:
				# the beast that rips the plaintext fields, dont ask.
				# takes atom length off the first two bytes
				atomL = (ord(atoms[0])*16) + ord(atoms[1])
				# increments the length counter
				# check the length of the fields for password and username maxlengths
				if ord(atoms[16]) == 12 or ord(atoms[16]) == 40:
					# get the length of the field
					fieldL = ord(atoms[15])
					# provided the length is sensible
					if fieldL > 0:
						if counter == 0:
							#credentialsFile.write("##### APPL4 Atom element, EField2 found from %s! #####\n\r" % ip_formatted)
							credentialsFile.write("\r\n" + "[+] " + src_ip_addr_str + " --> " + dst_ip_addr_str + "\r\n\r\n")
						# rip the appropriate field and write to file
						creds = atoms[(atomL-fieldL):atomL]
						credentialsFile.write(creds + "\r\n")
						counter = counter + 1
				# save current values for use in the while loop, and set up for the next atom to be read
				initialVal = atomL
				try:
					atomL = ord(atoms[atomL]) * 16 + ord(atoms[(atomL+1)])
				except Exception:
					atomL = 100000
				atoms = atoms[initialVal:]
			# maxim is here because encrypted traffic has caused major crashes here,
			# also, this ensures that the while loop does eventually end 
				maxim = maxim + 1
				totalAtoms = totalAtoms + atomL
		# if verbose is true, rip ALL cleartext fields
		if verbose == True:
			totalL = len(appl4pack)-7
			atoms = appl4pack[7:]
			totalAtoms = 0
			initialVal = 0
			maxim = 0
			counter = 0

			while totalAtoms < (totalL+1) and maxim < 10:
				atomL = (ord(atoms[0])*16) + ord(atoms[1])
				fieldL=ord(atoms[15])
				if fieldL > 0:
					if counter == 0:
						#verboseFile.write("##### APPL4 Atom element, EField2 found from %s! #####\n\r" % ip_formatted)
						verboseFile.write("\r\n" + "[+] " + src_ip_addr_str + " --> " + dst_ip_addr_str + "\r\n\r\n")
					creds = atoms[(atomL-fieldL):atomL]
					verboseFile.write(creds + "\n\r")
					counter = counter +1
				initialVal = atomL
				try:
					atomL = ord(atoms[atomL]) * 16 + ord(atoms[(atomL+1)])
				except Exception:
					atomL = 100000
				atoms = atoms[initialVal:]
				maxim = maxim + 1
				totalAtoms = totalAtoms + atomL

	elif code == 16:
		# if APPL get length and convert ip address to readable address
		# also, gear up for the big nonsense field ripper
		totalAtoms = 0
		initialVal = 0
		# takes atom length off the appropriate length bytes
		totalL = (ord(appl4pack[3])*16) + ord(appl4pack[4])
		# sets up the atom for dissection, and converts ip to readable address
		atoms = appl4pack[5:]
		octets = [source[i:i+2] for i in range(0, len(source), 2)]
		ip = [int(i, 16) for i in octets]
		ip_formatted = '.'.join(str(i) for i in ip)
		# another beast
		if ord(atoms[12]) < 127:
			while totalAtoms < (totalL+1) and maxim < 10:
				# take atom field length
				atomL = (ord(atoms[0])*16) + ord(atoms[1])
				# check the length of the fields for password and username maxlengths
				if ord(atoms[18]) == 12 or ord(atoms[18]) == 40:
					# get length of field
					fieldL = ord(atoms[15])
					# check for reasonable length of field
					if fieldL > 0:
						if counter == 0:
							#credentialsFile.write("##### APPL Atom element, EField2 found from %s! #####\n\r" % ip_formatted)
							credentialsFile.write("\r\n" + "[+] " + src_ip_addr_str + " --> " + dst_ip_addr_str + "\r\n\r\n")
						# rip and write creds
						creds = atoms[(atomL-fieldL):atomL]
						credentialsFile.write(creds + "\r\n")
						counter = counter + 1
					# gear up for the next atom if there is one
					initialVal = atomL
					try:
						atomL = ord(atoms[atomL]) * 16 + ord(atoms[(atomL+1)])
					except Exception:
						atomL = 100000
					atoms = atoms[initialVal:]
					# maxim is here because encrypted traffic has caused major crashes here,
					# also, this ensures that the while loop does eventually end 
				maxim = maxim + 1
				totalAtoms = totalAtoms + atomL
		if verbose == True:
			totalAtoms = 0
			initialVal = 0
			maxim = 0
			counter = 0
			totalL = (ord(appl4pack[3])*16) + ord(appl4pack[4])
			atoms = appl4pack[5:]
			while totalAtoms < (totalL+1) and maxim <10:
				atomL = (ord(atoms[0])*16) + ord(atoms[1])
				totalAtoms = totalAtoms + atomL
				fieldL = ord(atoms[15])
				if fieldL > 0:
					if counter == 0:
						#verboseFile.write("##### APPL Atom element, EField2 found from %s! #####\n\r" % ip_formatted)
						verboseFile.write("\r\n" + "[+] " + src_ip_addr_str + " --> " + dst_ip_addr_str + "\r\n\r\n")
					creds = atoms[(atomL-fieldL):atomL]
					verboseFile.write(creds + "\n\r")
					counter = counter + 1
				initialVal = atomL
				try:
					atomL = ord(atoms[atomL]) * 16 + ord(atoms[(atomL+1)])
				except Exception:
					atomL = 100000
				atoms = atoms[initialVal:]
			maxim = maxim + 1
			totalAtoms = totalAtoms + atomL

def parse(src_ip_addr_str, dst_ip_addr_str, currentFile, code, source, verbose):
	# this beast seperates each element and writes it out to file (debug) and returns whats left
	if code == 1:
		chunk = currentFile[0:17]
		outputFile.write("SES: %s\n\r" % chunk)
		return currentFile[17:]
	elif code == 2:
		chunk = currentFile[0:20]
		outputFile.write("ICO: %s\n\r" % chunk)
		return currentFile[20:]
	elif code == 3:
		chunk = currentFile[0:3]
		outputFile.write("TIT: %s\n\r" % chunk)
		return currentFile[3:]
	elif code == 7:
		chunk = currentFile[0:76]
		outputFile.write("DIAG_OLD: %s\n\r" % chunk)
		return currentFile[76:]
	elif code == 9:
		chunk = currentFile[0:22]
		outputFile.write("CHL: %s\n\r" % chunk)
		return currentFile[22:]
	elif code == 8:
		chunk = currentFile[0:0]
		outputFile.write("OKC: %s\n\r" % chunk)
		#return currentFile[0:]
		return "THEDOORS"
	elif code == 11:
		chunk = currentFile[0:9]
		outputFile.write("SBA: %s\n\r" % chunk)
		return currentFile[9:]
	elif code == 12:
		chunk = currentFile[0:0]
		outputFile.write("END OF MESSAGE\n\r")
		return "THEDOORS"
	elif code == 16:
		length = ord(currentFile[3])*16
		length2 = ord(currentFile[4])+length
		chunk = currentFile[0:(5+length2)]
		outputFile.write("APPL: %s\n\r" % chunk)
		#if ord(chunk[2])==9:
			#gui=chunk[5:8]
			#dump.write(gui)
		# these two bytes signify this is a DYNT, DYNT_ATOM element and worth checking
		# byte 10 signifies the EField version 0x79 and 0x82 for versions 1 and 2 respectively
		# the structure for containing info differs per version (:rolleyes:)
		if ord(chunk[2]) == 2 and ord(chunk[1]) == 9 and ord(chunk[9]) == 130:
			getCredsEField2(src_ip_addr_str, dst_ip_addr_str, chunk, code, source, verbose)
		if ord(chunk[2]) == 2 and ord(chunk[1]) == 9 and ord(chunk[9]) == 121:
			getCredsEField1(src_ip_addr_str, dst_ip_addr_str, chunk, code, source, verbose)
		return currentFile[(5+length2):]
	elif code == 17:
		length1 = ord(currentFile[1])*16*16*16
		length2 = ord(currentFile[2])*16*16
		length3 = ord(currentFile[3])*16
		length4 = ord(currentFile[4])+length3+length2+length1
		chunk = currentFile[0:(5+length4)]	
		outputFile.write("DIAG_XML: %s\n\r" % chunk)
		return currentFile[(5+length4):]
	elif code == 18:
		length1 = ord(currentFile[3])*16*16*16
		length2 = ord(currentFile[4])*16*16
		length3 = ord(currentFile[5])*16
		length4 = ord(currentFile[6])
		length4 = length1+length2+length3+length4
		chunk = currentFile[0:(7+length4)]	
		outputFile.write("APPL4: %s\n\r" % chunk)
		# APPL4 elements often and nearly always seem to contain atom fields, so check these too
		getCredsEField2(src_ip_addr_str, dst_ip_addr_str, chunk, code, source, verbose)
		return currentFile[(7+length4):]
	elif code == 21:
		chunk = currentFile[0:36]
		outputFile.write("SBA2: %s\n\r" % chunk)
		return currentFile[36:]
	else:
		return "THEDOORS"

def reverse(src_ip_addr_str, dst_ip_addr_str, currentbytes, source, verbose, creds_file):
	oldBytes = 0
	global credentialsFile
	global verboseFile
	try:
		# while not end of file, go through and dissect
		oldBytes = ""
		while currentbytes != "THEDOORS":
			# if oldBytes != currentbytes:
			credentialsFile = open(creds_file, "ab")
			verboseFile = open(verbose_file, "ab")
			currentbytes = parse(src_ip_addr_str, dst_ip_addr_str, currentbytes, ord(currentbytes[0]), source, verbose)
			oldBytes = currentbytes
			#credentialsFile.close
	except Exception:		
		pass