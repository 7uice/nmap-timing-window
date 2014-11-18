#!/usr/bin/python

import sys, re, os
from datetime import datetime



################################################
### Code to Enumerate IPs given a CIDR Block ###
################################################

# Expands a CIDR blocked IP into newline seperated IPs in that block.
# Copyright (c) 2007 Brandon Sterne
# Licensed under the MIT license.
# http://brandon.sternefamily.net/files/mit-license.txt
# CIDR Block Converter - 2007
#
# Modified by Nick Angelou nick.angelou@praetorian.com
# Will accept a file as input

# convert an IP address from its dotted-quad format to its
# 32 binary digit representation
def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length
def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

# convert a binary string into an IP address
def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

# print a list of IP addresses based on the CIDR block specified
def getCIDR(c):
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    # Python string-slicing weirdness:
    # "myString"[:-1] -> "myStrin" but "myString"[:0] -> ""
    # if a subnet of 32 was specified simply print the single IP
    if subnet == 32:
        return bin2ip(baseIP)
    # for any other size subnet, print a list of IP addresses by concatenating
    # the prefix with each of the suffixes in the subnet
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        t = ''
        for i in range(2**(32-subnet)):
            t += str(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
            t += '\n'
        return t

# input validation routine for the CIDR block specified
def validateCIDRBlock(b):
    # appropriate format for CIDR block ($prefix/$subnet)
    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):
        print "Error: Invalid CIDR format!"
        return False
    # extract prefix and subnet size
    prefix, subnet = b.split("/")
    # each quad has an appropriate value (1-255)
    quads = prefix.split(".")
    for q in quads:
        if (int(q) < 0) or (int(q) > 255):
            print "Error: quad "+str(q)+" wrong size."
            return False
    # subnet is an appropriate value (1-32)
    if (int(subnet) < 1) or (int(subnet) > 32):
        print "Error: subnet "+str(subnet)+" wrong size."
        return False
    # passed all checks -> return True
    return True

def printUsage():
    print "Usage: ./cidr.py <prefix>/<subnet>\n  e.g. ./cidr.py 10.1.1.1/28" + \
          "\n  e.g. ./cidr.py 192.168.1/24"
    
def enumerate_ips():
    # get the CIDR block from the command line args
    try:
        inFile = sys.argv[1]
    # if not specified on the CLI -> prompt the user for CIDR block
    except:
        inFile = raw_input("Input File conntaining CIDR Blocks: ")
    # input validation returned an error
    with open(inFile) as f:
      cidrBlock = f.read().splitlines()

    for cidrLine in cidrBlock:
        if not validateCIDRBlock(cidrLine):
            printUsage()
        # print the user-specified CIDR block
        else:
            return getCIDR(cidrLine)

################################################

def scan_block(block_index, target_path, nmap_command):
	target = target_path + 'ip_block_' + str(block_index)
	if os.path.exists(target):
		if not os.path.exists('completed_scans'):
			os.makedirs('completed_scans')
		nmap_command += ' -oN completed_scans/scan_block_' + str(block_index) + ' -iL ' + target
		print nmap_command
		os.system(nmap_command)
		if not os.path.exists('ip_blocks/scanned_blocks'):
			os.makedirs('ip_blocks/scanned_blocks')
		os.system('mv ' + target + ' ip_blocks/scanned_blocks/ip_block_' + str(block_index))
		return True
	else:
		print '[e]: Target file ' + target + ' cannot be found.'
		return False

def clean():
	if os.path.exists('ip_blocks'):
		os.system('rm -r ip_blocks')
	if os.path.exists('completed_scans'):
		os.system('rm -r completed_scans')

def main():
	print '****************************'
	print '*** Nmap Time Controller ***'
	print '****************************'
	print '\n'
	

	if sys.argv[1] == 'clean':
		print 'Cleaning project...'
		clean()
		print 'Done.\n\n'
		exit()

	######################################################################
	### Enumerate IPs and split into groups of 8 for nmap to work with ###
	######################################################################
	ips = enumerate_ips().splitlines()
	valid_time_beginning = raw_input('What time should the scan START? (Please use military time format i.e. 22:00)\n')
	valid_time_end = raw_input('What time should the scan END?\n')
	nmap_command = raw_input('Enter in the nmap command for the scan: (i.e. nmap -sC \nDo not include target specifications or output specifications. We take care of that.\n')
	# Hard coded to avoid repeatedly inputting while testing
	valid_time_beginning = datetime.strptime('11:00', '%H:%M').time()
	valid_time_end = datetime.strptime('13:16', '%H:%M').time()
	nmap_command = 'nmap -sC'

	print 'IPs to scan:\n', ips
	print 'Scan window: ', valid_time_beginning.strftime('%H:%M'), ' - ', valid_time_end.strftime('%H:%M')
	print 'Nmap command: ', nmap_command		

	# FIX THIS LATER
	# Currently leaves off IPs (only gets all IPs when divisible by 8)
	# Put IPs in groups of 8. Keep them in groups of 8 so nmap can do it's parallelization magic while scanning.
	counter = 0
	ip_block = ''
	block_index = 0
	for ip in ips:
		if counter < 8:
			ip_block += (str(ip) + '\n')
			counter += 1
		else:
			if not os.path.exists('ip_blocks/unscanned_blocks'):
				os.makedirs('ip_blocks/unscanned_blocks')
			file_name = 'ip_blocks/unscanned_blocks/ip_block_' + str(block_index)
			f = open(file_name, 'w')
			f.write(ip_block)
			f.close()
			ip_block = ''
			counter = 0
			block_index += 1

	###################################################################
	### Start the scanning process while monitoring time boundaries ###
	###################################################################
	
	# if current_time is in range, start a single scan
	# when the scan is finished, move the block of ips that was scanned to the 'completed' folder
	# Also write the results to a file
	# repeat until a) No ip blocks are left or b) we run out of time
	# once all IP blocks are done, we'll combine the files

	current_time = datetime.now().time()
	block_index = 0
	target_path = 'ip_blocks/unscanned_blocks/'

	while (current_time > valid_time_beginning) and (current_time < valid_time_end) and os.listdir(target_path) != []: 
		print 'Debug WHILE loop:'
		# a = current_time > valid_time_beginning
		# b = current_time < valid_time_end
		# c = os.listdir(target_path) != []
		# print '\na: ' + str(a)
		# print 'b: ' + str(b)
		# print 'c: ' + str(c)
		# print '\n\n'
		scan_block(block_index, target_path, nmap_command)
		block_index += 1
		current_time = datetime.now().time()
	

if __name__ == "__main__":
	main()



