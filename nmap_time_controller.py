#!/usr/bin/python

import sys, re, os, time, glob
from datetime import datetime



################################################
### Code to Enumerate IPs given a CIDR Block ###
################################################

# Code to enumerate IPs given a CIDR Block from:
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
    
def enumerate_ips(in_file):
    # get the CIDR block from the command line args
    try:
        inFile = in_file
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
		nmap_command += ' -oA completed_scans/scan_block_' + str(block_index) + ' -iL ' + target
		print nmap_command
		os.system(nmap_command)
		if not os.path.exists('ip_blocks/scanned_blocks'):
			os.makedirs('ip_blocks/scanned_blocks')
		os.system('mv ' + target + ' ip_blocks/scanned_blocks/ip_block_' + str(block_index))
		return True
	else:
		print '[e]: Target file ' + target + ' cannot be found. If you used the RESUME option, this file was most likely already scanned.'
		return False

def new_scan():
	######################################################################
	### Enumerate IPs and split into groups of 8 for nmap to work with ###
	######################################################################
	global scan_window_start
	global scan_window_end
	global nmap_command

	if len(sys.argv) < 3:
		print '[ERROR]: Please specify a target file'
		print 'exiting...'
		exit()

	if not os.path.exists(sys.argv[2]):
		print '[ERROR]: File not found: ' + sys.argv[2]
		print 'exiting...'
		exit()	

	a = raw_input('[WARNING]: Starting a new scan will wipe the results/progress of any current or past scan.\nAre you sure you want to continue? (Y/n) ')
	if(a == 'Y' or a == 'y' or a == ''):
		clean(True)
	else:
		print 'exiting without cleaning...'
		exit()

	print '\nStarting new scan...\n'
	ips = enumerate_ips(sys.argv[2]).splitlines()
	scan_window_start = raw_input('What time should the scan START? (Please use military time format i.e. 22:00)\n')
	scan_window_end = raw_input('What time should the scan END?\n')
	nmap_command = raw_input('Enter in the nmap command for the scan: (i.e. nmap -sC) \nDo not include TARGET specifications or OUTPUT specifications. We take care of that.\n')
	# Hard coded to avoid repeatedly inputting while testing
	scan_window_start = datetime.strptime(scan_window_start, '%H:%M').time()
	scan_window_end = datetime.strptime(scan_window_end, '%H:%M').time()
	# nmap_command = 'nmap -sC'

	if not os.path.exists('program_data'):
		os.makedirs('program_data')
		filename = 'program_data/scan_window_start'
		f = open(filename, 'w')
		f.write(scan_window_start.strftime('%H:%M'))
		filename = 'program_data/scan_window_end'
		f = open(filename, 'w')
		f.write(scan_window_end.strftime('%H:%M'))
		filename = 'program_data/nmap_command'
		f = open(filename, 'w')
		f.write(nmap_command)

	# print 'IPs to scan:\n', ips
	# print 'Scan window: ', scan_window_start.strftime('%H:%M'), ' - ', scan_window_end.strftime('%H:%M')
	# print 'Nmap command: ', nmap_command		

	# Put IPs in groups of 8. Keep them in groups of 8 so nmap can do it's parallelization magic while scanning.
	counter = 0
	ip_block = ''
	block_index = 0
	for ip in ips:
		if counter < 8: # Add IP to ip_block until we have 8 of them
			ip_block += (str(ip) + '\n')
			counter += 1
		else: # We have 8 IPs in the ip_block. Write it to file
			if not os.path.exists('ip_blocks/unscanned_blocks'):
				os.makedirs('ip_blocks/unscanned_blocks')
			filename = 'ip_blocks/unscanned_blocks/ip_block_' + str(block_index)
			f = open(filename, 'w')
			f.write(ip_block)
			f.close()
			ip_block = ''
			counter = 0
			block_index += 1
	# Catch all IPs at the end (for CIDR blocks that are not exact multiples of 8)
	if not os.path.exists('ip_blocks/unscanned_blocks'):
		os.makedirs('ip_blocks/unscanned_blocks')
	filename = 'ip_blocks/unscanned_blocks/ip_block_' + str(block_index)
	f = open(filename, 'w')
	f.write(ip_block)
	f.close()

	scan_loop()


# [DESC] scan_loop()
# Start the scanning process while monitoring time boundaries
# if current_time is in range, start a single scan
# when the scan is finished, move the block of ips that was scanned to the 'completed' folder
# Also write the results to a file
# repeat until a) No ip blocks are left or b) we run out of time
# once all IP blocks are done, we'll combine the files
def scan_loop():
	current_time = datetime.now().time()
	block_index = 0
	target_path = 'ip_blocks/unscanned_blocks/'

	while (current_time > scan_window_start) and (current_time < scan_window_end) and os.listdir(target_path) != []: 
		scan_block(block_index, target_path, nmap_command)
		block_index += 1
		current_time = datetime.now().time()

	a = current_time > scan_window_start
	b = current_time < scan_window_end
	c = os.listdir(target_path) != []
	if (not a) or (not b):
		print 'Exiting because current_time is outside of valid scan_time window'
		wait_for_valid_window()
	if not c:
		print 'Exiting because all targets have been scanned'
		combine()


def wait_for_valid_window():
	global scan_window_start
	global scan_window_end	

	current_time = datetime.now().time()
	while True:
		if (current_time > scan_window_start) and (current_time < scan_window_end):
			break
		else:
			print '\nWaiting for valid scan window'
			print 'Current time: ' + current_time.strftime('%H:%M')
			print 'Scan window: ' + scan_window_start.strftime('%H:%M') + ' - ' + scan_window_end.strftime('%H:%M')
			time.sleep(15)
		scan_loop()

def combine():
	if not os.path.exists('completed_scans') or os.listdir('completed_scans') == []:
		print 'No block scans have been completed.\nStart the block scanning process with ./nmap_time_controller new [target file] or ./nmap_time_controller resume.'
		print 'exiting...'
		exit()
	if os.path.exists('completed_scans/scan_results.nmap'):
		os.remove('completed_scans/scan_results.nmap')
	if os.path.exists('completed_scans/scan_results.gnap'):
		os.remove('completed_scans/scan_results.gnap')
	if os.path.exists('completed_scans/scan_results.xml'):
		os.remove('completed_scans/scan_results.xml')
	combine_nmap()
	combine_gnmap()
	combine_xml()
	print 'output block files combined and saved in completed_scans/scan_results.[nmap, gnmap, xml]. Enjoy.'	


def combine_nmap():
	filenames = []
	for filename in glob.glob('completed_scans/*.nmap'):
		filenames.append(filename)
	with open('completed_scans/scan_results.nmap', 'w') as outfile:
		for fname in filenames:
			with open(fname) as infile:
				for line in infile:
					outfile.write(line)
	   	outfile.write('\n')	
		
def combine_gnmap():
	filenames = []
	for filename in glob.glob('completed_scans/*.gnmap'):
		filenames.append(filename)
	with open('completed_scans/scan_results.gnmap', 'w') as outfile:
		for fname in filenames:
			with open(fname) as infile:
				for line in infile:
					outfile.write(line)
	   	outfile.write('\n')	

# A bit tricky and a bit messy
def combine_xml():
	filenames = []
	for filename in glob.glob('completed_scans/*.xml'):
		filenames.append(filename)
	with open('completed_scans/scan_results.xml', 'w') as outfile:
		for fname in filenames:
			with open(fname) as infile:
				for line in infile:
					outfile.write(line)
	   	outfile.write('\n')	
   	# Get rid of repeated lines (Results from concating xml files together) and stuff we don't need
   	line_number = 1
   	lines_to_remove = []
   	with open('completed_scans/scan_results.xml', 'r') as f:
   		for line in f:
   			if ("<?xml version=" in line and line_number != 1):
   				lines_to_remove.append(line_number)
   			elif ("<!DOCTYPE nmaprun>" in line and line_number != 2):
   				lines_to_remove.append(line_number)
   			elif ("<nmaprun " in line and (not (line_number < 10))):
   				lines_to_remove.append(line_number)
   			elif ("</nmaprun>" in line):
   				lines_to_remove.append(line_number)
			elif ("<scaninfo " in line):
				lines_to_remove.append(line_number)
			elif ("<?xml-stylesheet " in line):
				lines_to_remove.append(line_number)
			line_number += 1
	# Remake file without unnecessary lines
	#os.remove('completed_scans/scan_results.xml')
	f = open('completed_scans/scan_results.xml', 'r')
	lines = f.readlines()
	f.close()
	f = open('completed_scans/scan_results_cleaned_up.xml', 'w')
	line_number = 1
	for line in lines:
		if line_number not in lines_to_remove:
			f.write(line)
		line_number+=1
	f.write("</nmaprun>")
	f.close()


   		#increment line number
   		#append '</nmaprun>' at the end



def clean(confirm = False):
	if not confirm:
		a = raw_input('[WARNING]: Cleaning will wipe the results/progress of any current or past scan.\nAre you sure you want to continue? (Y/n) ')
		if(a == 'Y' or a == 'y' or a == ''):
			pass
		else:
			print 'exiting without cleaning...'
			exit()

	print 'Cleaning project...'
	if os.path.exists('ip_blocks'):
		os.system('rm -r ip_blocks')
	if os.path.exists('completed_scans'):
		os.system('rm -r completed_scans')
	if os.path.exists('program_data'):
		os.system('rm -r program_data')
	print 'Done.'

def print_usage():
	print '[DESCIPTION]:\nNmap Time Controller takes a list of targets and a specified time window and will run port scans only during the specified time window.\nThe program take the list of targets and breaks it up into blocks of 8 IPs at a time so that nmap can parallelize the scanning.\nEach scan on a block of 8 IPs is written to an individual output file in completed_scans folder and is then combined at the end.\nThe final combined output will be completed_scans/scan_results. Enjoy!\n\n'
	print '[USAGE]:'
	print 'Start a new scan:'
	print './nmap_time_controller new [target_file]\n'
	print 'Resume a scan:'
	print './nmap_time_controller resume\n'
	print 'Combine block output of a scan:'
	print './nmap_time_controller combine\n'
	print 'Clean up with:'
	print './nmap_time_controller clean\n'

def main():
	print '\n'
	print '****************************'
	print '*** Nmap Time Controller ***'
	print '****************************'
	print '\n'



	if len(sys.argv) < 2:
		print_usage()
		exit()

	if sys.argv[1] == 'new':
		new_scan()

	if sys.argv[1] == 'resume':
		global scan_window_start
		global scan_window_end
		global nmap_command
		scan_window_start = datetime.strptime(open('program_data/scan_window_start', 'r').read().rstrip(), '%H:%M').time()
		scan_window_end = datetime.strptime(open('program_data/scan_window_end', 'r').read().rstrip(), '%H:%M').time()
		nmap_command = open('program_data/nmap_command', 'r').read()
		nmap_command.close()
		print '\nResuming scan...\n\n'
		scan_loop()

	if sys.argv[1] == 'combine':
		combine()

	if sys.argv[1] == 'clean':
		clean()
		exit()

	# Globals
	scan_window_start = None 
	scan_window_end = None
	nmap_command = None 



if __name__ == "__main__":
	main()



