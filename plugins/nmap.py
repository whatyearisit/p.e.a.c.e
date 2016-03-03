# -*- coding: utf-8 -*-
import sys
from termcolor import colored, cprint
import os
import shlex
import time
import threading
import Queue
from output import *

class NmapScanner(object):

	def __init__(self, project_name):
		self.project_name = project_name
		self.targets = []
		self.nmap_arguments = []
		self.tcp_scan_queue = Queue.Queue()
		self.udp_scan_queue = Queue.Queue()

		if not os.path.isdir(self.project_name):
			os.mkdir(self.project_name)
		self.print_logo()

	def print_logo(self):
		print("""\
			\n\n(◕‿-) P.E.A.C.E v0.1 (◕‿-)\n
		""")

	def add_host(self, target):
		self.targets.append(target)

	#def add_hosts_from_list(self, file):
	#	self.file = file

	def get_targets(self):
		print "targets:"
		if self.targets:
			for element in self.targets:
				print element
		else:
			print "no target(s) found."
	

	def set_scan_type(self, scan_type):
		
		if 'tcp_syn_full' in scan_type:
			#syn scan - version detection - full port range - os detection - no ping"
			self.nmap_arguments.append("nmap -sS -sV -Pn -p 1-65535 -T3 -v -O -oA %s/%s" %(self.project_name, "tcp_full_range_"))

			#syn scan - nse scripts - version detection, full port range
			self.nmap_arguments.append("nmap -sS -sC -sV -Pn -p 1-65535 -T3 -v -oA %s/%s" %(self.project_name, "tcp_nse_scan_"))

		elif 'udp_common_ports' in scan_type:
			#udp scan - version detection - aggressive
			self.nmap_arguments.append("nmap -sU -sV -Pn -T5 -v --max-retries 5 --host-timeout 10s -oA %s/%s" %(self.project_name, "udp_scan_"))
		
		elif 'test' in scan_type:
			#simple fast tcp scan for testing purposes
			self.nmap_arguments.append("nmap -sS -p 21,80,443 -oA %s/%s" %(self.project_name, "test_"))

		else:
			print "[-] Invalid scan type supplied"
			print_info("Currently supported scan types:")
			print "tcp_syn_full: "
			print "* syn scan - service detection - full port range - os detection - no ping - nse scripts" 
			print "udp_common_ports "
			print "* udp scan - service detection - aggressive (T5)"
	

	def start_scan(self):
		for target in self.targets:
                        for nmap_arg in self.nmap_arguments:
                                #append target to nmap scan commands
                                nmap_arg += "%s %s" %(target,target)
                                if 'sU' in nmap_arg:
                                        self.udp_scan_queue.put(nmap_arg)
                                else:
                                        self.tcp_scan_queue.put(nmap_arg)
		#start worker threads that execute nmap scans	
		self._tcp_scan_worker(2)
		self._udp_scan_worker(1)
		
		self.tcp_scan_queue.join()
		print_success("TCP scans successfully finished!")
		self.udp_scan_queue.join()
		print_success("UDP scans successfully finished!")
		
	def _tcp_scan_worker(self, maxThreads):
		for i in range(maxThreads):
			tcp_scan = threading.Thread(target=self.start_nmap_tcp)
			tcp_scan.start()
	
	def _udp_scan_worker(self, maxThreads):
		for i in range(maxThreads):
			udp_scan = threading.Thread(target=self.start_nmap_udp)
			udp_scan.start()

	def start_nmap_tcp(self):
		while not self.tcp_scan_queue.empty():
			nmap_args = self.tcp_scan_queue.get()
			print_info("starting TCP scan on: \n%s" %nmap_args)
			nmap_args += " > /dev/null 2>&1"
			os.system(nmap_args)
			self.tcp_scan_queue.task_done()

	def start_nmap_udp(self):
		while not self.udp_scan_queue.empty():
			nmap_args = self.udp_scan_queue.get()
			#print ""
			print_info("starting UDP scan on: \n%s" %nmap_args)
			nmap_args += " > /dev/null 2>&1"
			os.system(nmap_args)
			self.udp_scan_queue.task_done()


#targets = ["192.168.0.1", "192.168.1.1", "192.168.1.202"]

#nm = NmapScanner("testproject")
#nm.set_scan_type('tcp_syn_full')
#nm.set_scan_type('udp_common_ports')
#nm.set_scan_type('test')

#for target in targets:
#	nm.add_host(target)
#nm.start_scan()
