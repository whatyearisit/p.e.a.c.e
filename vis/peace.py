from plugins.nessus import AutoNessus
from plugins.nmap import NmapScanner
from plugins.ovas import AutoOpenvas
from plugins.output import *

targets = ["192.168.43.245"]
ovas = AutoOpenvas()
nessus = AutoNessus()
nm = NmapScanner("test")

#nmap settings
nm.set_scan_type('tcp_syn_full')
nm.set_scan_type('udp_common_ports')
#nm.set_scan_type('test')

#nessus settings
nessus.set_policy("nw_full_scan_slow")

print_info("adding hosts to P.E.A.C.E")
for target in targets:
	print target
        nm.add_host(target)
	nessus.add_host(target)
	ovas.add_host(target)
print ""

nm.start_scan()			#start nmap scans first
nessus.start_scan(1)		#start nessus scan after nmap finished
ovas.start_scan()		#start openvas scan after nessus finished
