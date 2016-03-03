import MySQLdb
from libnmap.parser import NmapParser
from libnessus.parser import NessusParser
import os
from termcolor import colored


#pip2 install python-libnessus

class MySQLConnector():

	db = None
	cursor = None


	def __init__(self):
		#print "[*] connecting to db.."
		try:
			self.db = MySQLdb.connect("127.0.0.1", "root", "dinimere", "P.E.A.C.E")
		except Exception,e:
			print "mysql connection failed. error:"
			print e
		#print "[+] db connection established!\n"
		self.cursor = self.db.cursor()



	def insert_nmap_data(self, ip_addr, protocol, port_nr, state, service_name, banner, os, nse):
		stmt = "INSERT INTO nmap(ip,proto,port,state,service_name,banner,os,nse) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)"
		try:
			print "[*] inserting nmap data into the database"
			self.cursor.execute(stmt, (ip_addr, protocol, port_nr, state, service_name, banner, os, nse))
			self.db.commit()
		except Exception,e:
			self.db.rollback()
			print e


	#imports all xml files from a given directory
	def import_nmap_xml(self, path_to_directory):

		#nmap_report = NmapParser.parse_fromfile(path_to_directory)
		
		for file in os.listdir(path_to_directory):
			if file.endswith(".xml"):
				print "\n[*] importing file: %s\n" %file
				file = "%s%s" %(path_to_directory, file)
				nmap_report = NmapParser.parse_fromfile(file)

				for host in nmap_report.hosts:
					ip = host.address
					open_ports = host.get_ports()
					os_fingerprint = host.os_fingerprint
					services = host.services

					for service in services:
						nse_output = ''
						for element in service.scripts_results:
							nse_output = "%s \n%s" %(element['id'], element['output'])
							##
							# Verbode Mode (print)
							##
							#print ip, service.protocol, service.port, service.state, service.service, service.banner, os_fingerprint, nse_output
							self.insert_nmap_data(ip, service.protocol, service.port, service.state, service.service, service.banner, os_fingerprint, nse_output)


	def insert_nessus_data(self, ip, proto, port, service, vuln_risk_factor, vuln_plugin_name, vuln_description, vuln_risk, vuln_solution, vuln_patch_pub_date, vuln_plugin_output, vuln_cvss_score, vuln_cve, vuln_osvdb, vuln_exploitability, vuln_exploit_available, vuln_metasploit_availability, vuln_metasploit_name, vuln_references):
		
                stmt = "INSERT INTO `P.E.A.C.E`.`nessus` (`ip`, `proto`, `port`, `service`, `risk_factor`, `plugin_name`, `description`, `risk`, `solution`, `patch_pub_date`, `plugin_output`, `cvss_score`, `cve`, `osvdb`, `exploitability`, `exploit_available`, `metasploit_availability`, `metasploit_name`, `references`) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
		stmt = MySQLdb.escape_string(stmt)
                try:
                        print "[*] inserting nessus data into the database"
                        self.cursor.execute(stmt, (ip, proto, port, service, vuln_risk_factor, vuln_plugin_name, vuln_description, vuln_risk, vuln_solution, vuln_patch_pub_date, vuln_plugin_output, vuln_cvss_score, vuln_cve, vuln_osvdb, vuln_exploitability, vuln_exploit_available, vuln_metasploit_availability, vuln_metasploit_name, vuln_references))
                        self.db.commit()
                except Exception,e:
                        #self.db.rollback()
                        print e


	def import_nessus(self, path_to_directory):
		for file in os.listdir(path_to_directory):
			if file.endswith(".nessus"):
				print "\n[*] importing nessus file: %s\n" %file
				file = "%s%s" %(path_to_directory, file)
				report = NessusParser.parse_fromfile(file)
				
				for host in report.hosts:
					ip = host.ip

					os_fingerprint = host.get_host_property('operating-system')
					for vuln in host.get_report_items:
						service = vuln.service
						proto = vuln.protocol
						vuln_info = vuln.get_vuln_info
						port = vuln_info['port']

						#############################
						#Vulnerability Infos
						#############################
						#vuln db references
						vuln_cvss_score = ''
						vuln_cve = ''
						vuln_osvdb = ''
			
						if 'cvss_base_score' in vuln_info:
                                                        vuln_cvss_score = vuln_info['cvss_base_score']

                                                if 'cve' in vuln_info:
                                                        vuln_cve = ', '.join(vuln_info['cve'])

                                                if 'osdvdb' in vuln_info:
                                                        vuln_osvdb = ', '.join(vuln_info['osvdb'])

						##################
						#vuln descriptions
						##################
						vuln_description = ''
						vuln_plugin_output = ''		
						vuln_solution = ''
						vuln_risk = ''
						vuln_metasploit_availability = ''
						vuln_patch_pub_date = ''
						vuln_exploit_available = ''						
						vuln_metaasploit_name = ''
						vuln_risk_factor = ''
						vuln_exploitability = ''
						vuln_metasploit_name = ''
						vuln_references = ''
						vuln_plugin_name = ''
						vuln_metasploit_name = ''

						if 'description' in vuln_info:
							vuln_description = vuln_info['description']
						
						if 'plugin_name' in vuln_info:
							vuln_plugin_name = vuln_info['plugin_name']

						if 'plugin_output' in vuln_info:
							vuln_plugin_output = vuln_info['plugin_output']

						if 'solution' in vuln_info:
							vuln_solution = vuln_info['solution']

						if 'synopsis' in vuln_info:
							vuln_risk = vuln_info['synopsis']

						if 'exploit_framework_metasploit' in vuln_info:	
							vuln_metasploit_availability = str(vuln_info['exploit_framework_metasploit']) #True or False

						if 'patch_publication_date' in vuln_info:
							vuln_patch_pub_date = vuln_info['patch_publication_date']
						
						if 'exploit_available' in vuln_info:
							vuln_exploit_available = vuln_info['exploit_available'] #true or false
						
						if 'metasploit_name' in vuln_info:
							vuln_metasploit_name = vuln_info['metasploit_name']
						
						if 'risk_factor' in vuln_info:
							vuln_risk_factor = vuln_info['risk_factor']

						if 'see_also' in vuln_info:
							vuln_references = vuln_info['see_also']

						if 'exploitability_ease' in vuln_info:
							vuln_exploitability = vuln_info['exploitability_ease']
		
						self.insert_nessus_data(ip, proto, port, service, vuln_risk_factor, vuln_plugin_name, vuln_description, vuln_risk, vuln_solution, vuln_patch_pub_date, vuln_plugin_output, vuln_cvss_score, vuln_cve, vuln_osvdb, vuln_exploitability, vuln_exploit_available, vuln_metasploit_availability, vuln_metasploit_name, vuln_references)
		
						##
						## verbose mode
						##
						#print "\n================================"
						#print ip, port, proto, service, vuln_risk_factor, vuln_plugin_name, vuln_description, vuln_risk, vuln_solution, vuln_patch_pub_date, vuln_plugin_output, vuln_cvss_score, vuln_cve, vuln_osvdb, vuln_exploitability, vuln_exploit_available, vuln_metasploit_availability, vuln_metasploit_name, vuln_references 
						#print "=================================="

	
##############Search for Exploits based on CVE's found by nessus #############################
	#tested only in kali
	def search_exploit_by_cve(self):
		filepath_msf3_exploits = "/usr/share/metasploit-framework/modules/exploits"
		filepath_exploit_db = "/usr/share/exploitdb/platforms"
		cve_list = []
		stmt = "SELECT cve FROM nessus"
		#Get all CVEs from the nessus database
		try:
                        self.cursor.execute(stmt)
			result = self.cursor.fetchall()
			for cve in result:
				cve = str(cve).replace("('","").replace("',)","")
				if ',' in cve:
					cves = cve.split(',')
					for cve in cves:	
						cve = cve.replace(' ','')
						cve_list.append(cve)
				
				if cve and not ',' in cve:
					cve = cve.replace(' ','')
					cve_list.append(cve)

			#self.db.commit()
                except Exception,e:
                        self.db.rollback()
                        print e

		print colored("\n[*] searching metasploit modules", 'green')
                cves = list(set(cve_list))
                for cve in cves:
                        cve = cve.replace('CVE-','')
                        os.system("grep -r "+cve+" "+filepath_msf3_exploits)

		print colored("\n[*] searching exploit-db based on cves", 'green')
		for cve in cves:
			cve = cve.replace('CVE-','')
			os.system("grep -r "+cve +" "+filepath_exploit_db)



db = MySQLConnector()
#db.import_nmap_xml('/media/sda3/peace/test/')
#db.import_nessus('/media/sda3/peace/test/')
db.search_exploit_by_cve()
