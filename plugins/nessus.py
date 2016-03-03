import nessrest
from nessrest import ness6rest
import threading
import Queue
from threading import Semaphore
import time
from output import *

#Dependencies:
#git clone https://github.com/golismero/openvas_lib.git
#python setup.by build
#python setup.py install
#or:
#pip install openvas_lib


class AutoNessus():

	def __init__(self):
		self.anessus = ness6rest.Scanner(url='https://127.0.0.1:8834', login='admin', password='dinimere', insecure=True)
		self.policy = False
		self.username = ''
		self.pw = ''
		self.scanning_queue = Queue.Queue()
		self.targets = []
		

	def add_host(self, target):
		self.scanning_queue.put(target)
		self.targets.append(target)
	

	def start_scan(self, parallelScans):
		print_info("starting nessus scans..")
		if self.policy:
			t = threading.Thread(target=self._nessus_worker)
			t.start()
			t.join() #finish thread
		else:
			print "[-] You must define a nessus policy BEFORE you can run a scan. Use method: set_policy first!"

	def set_policy(self, name):
		self.policy = self.anessus.policy_set(name)
		self.policy = True

	def _nessus_worker(self):
		targets = ','.join(map(str, self.targets))
		self.anessus.scan_add(targets=targets)
		self.anessus.scan_run()
		scan_results = self.anessus.scan_results()


#test cases
#targets = ["192.168.0.1", "192.168.1.1", "192.168.1.202"]

#nessus = AutoNessus()
#nessus.set_policy("nw_full_scan_slow") #scans host by host.

#for target in targets:
#	print "adding host: %s" %target
#	nessus.add_host(target)

#nessus.start_scan(1)

