#Dependencies:
#openvas_lib
#pip install openvas_lib (or install from github)

import sys
import threading
import Queue
from openvas_lib import VulnscanManager, VulnscanException
from output import *


class AutoOpenvas():
	
	def __init__(self):
		self.targets = []

	def add_host(self, target):
		self.targets.append(target)

	def start_scan(self):
		print_info("connecting to openvas..")
		try:
                        self.scanner = VulnscanManager('127.0.0.1', 'admin', 'dinimere')
                except VulnscanException, e:
                        print "Error:"
                        print e
		print_success("connected to openvas")
		print ""
		print_info("starting openvas scan...")
		t = threading.Thread(target=self._openvas_worker)
		t.start()

	def _openvas_worker(self):
		targets = ','.join(self.targets)
		target_id = self.scanner.launch_scan(target="%s"%targets, profile="nw_scan_deep")


#targets = ["192.168.1.202", "192.168.1.64", "192.168.1.1"]

#openvas = AutoOpenvas()
#for target in targets:
#	openvas.add_host(target)

#openvas.start_scan()

