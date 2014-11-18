#!/usr/bin/python

import sys, re, os



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



def main():
	print 'Nmap Time Controller'
	ips = enumerate_ips()
	valid_time_beginning = raw_input('What time should the scan START? (Please use military time format i.e. 22:00)\n')
	valid_time_end = raw_input('What time should the scan END?\n')
	nmap_string = raw_input('Enter in the nmap command for the scan: (i.e. nmap -sC -oN scan_results.nmap\nDo not include target specifications. We take care of that.\n')

	print 'IPs to scan:\n', ips
	print 'Scan window: ', valid_time_beginning, ' - ', valid_time_end
	print 'Nmap command: ', nmap_string		

	# Put IPs in groups of 8. Keep them in groups of 8 so nmap can do it's parallelization magic while scanning.
	# index = 0
	# group_index = 0
	# ip_group = '' # Groups of 8 IPs
	# for ip in ips:
	# 	if index < 8: # Keep going until we have a group of 8 IPs
	# 		ip_group += ip
	# 		index += 1
	# 	else: # We have a block of 8. Write it to file and get the next block
	# 		if not os.path.exists('IP_Blocks'):
	# 			os.makedirs('IP_Blocks')
	# 		file_name = 'IP_Block_' + str(group_index)
	# 		f = open(file_name, 'w')
	# 		f.write(ip_group)
	# 		f.close()
	# 		index = 0
	# 		group_index += 1
	# 		ip_group = ''

	# counter = 0
	# ip_block = ''
	# for ip in ips:
	# 	if counter < 8:
	# 		ip_block += (str(ip) + '\n')
	# 		counter += 1
	# 	else:
	# 		print 'Block of 8:'
	# 		print ip_block
	# 		ip_block = ''
	# 		counter = 0

	print 'Test'
	for ip in ips:
		print ip



	

if __name__ == "__main__":
	main()



