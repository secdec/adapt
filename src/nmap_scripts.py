#
#  Automated Dynamic Application Penetration Testing (ADAPT)
#
#  Copyright (C) 2018 Applied Visions - http://securedecisions.com
#
#  Written by Siege Technologies - http://www.siegetechnologies.com/
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import subprocess
import nmap
from pprint import pprint

def translate_url(url):
	if(url.startswith("https://")):
		url = url[8:]
	elif(url.startswith("http://")):
		url = url[7:]

	url_parts = url.split("/")

	if(url_parts[0].startswith("www.")):
		url = url_parts[0][4:]
	else:
		url = url_parts[0]

	return url

def find(data):
	try:
		for k,v in data.items():
			if(k == "script"):
				yield v
			elif(isinstance(v, dict)):
				for result in find(v):
					yield result
			elif(isinstance(v, list)):
				for d in v:
					for result in find(d):
						yield result
	except AttributeError:
		yield data

class nmap_scripting():
	def __init__(self, target, ports, scripts_to_run=None):
		if(ports != None):
			self.port_values = "-p"+",".join(ports.split())
		else:
			self.port_values = ""
		self.target = translate_url(target)
		self.nm = nmap.PortScanner()
		self.__valid_scripts = []
		if(scripts_to_run == None):
			# for current project goals only one script is run
			# The idea beaing that any future development or tests can 
			# just call an nmap script and use its information 
			self.__valid_scripts = [
				#"ssl-cert", 					# getthe target's ssl certificate 
				#"ssl-ccs-injection",			# determines if vulnerable to ccs injection (CVE-2014-0224)
				#"ssl-cert-intaddr",				# reports any private ipv4 addrs in the ssl certificate 
				#"ssl-dh-params",				# Weak Diffe-Hellman handshake detection
				#"ssl-enum-ciphers",				# Tries multiple ssl/tsl ciphers and ranks available 
				#"ssl-heartbleed",				# detects if app is vuln to heartbleed 
				#"ssl-known-key",				# checks to see if certificate has any known bad keys 
				#"ssl-poodle",					# checks if app is vuln to poodle 
				#"sslv2-drown",					# checks if app supports sslv2 and is vuln to drown
				#"sslv2",						# checks if it supports older and outdated sslv2
				#"http-vuln-cve2006-3392",		# checks for directory information given by Webmin 
				#"http-vuln-cve2009-3960",		# adobe XML external entity injection 
				#"http-vuln-cve2010-0738",		# checks if Jboss target is vuln to jmx console auth bypass
				#"http-vuln-cve2010-2861",		# Directory draversal agains ColdFusion server 
				#"http-vuln-cve2011-3192",		# Detects DoS vuln on Apache systems 
				#"http-vuln-cve2011-3368",		# Checks Reverse Proxy Bypass on Apache
				#"http-vuln-cve2012-1823",		# Checks for PHP-CGI vulns
				#"http-vuln-cve2013-0156",		# Checks for Ruby object injections 
				#"http-vuln-cve2013-6786",		# Redirection and XXS
				#"http-vuln-cve2013-7091",		# Zero data for local file retrieval 
				#"http-vuln-cve2014-2126",		# Cisco ASA privilege escalation vuln 
				#"http-vuln-cve2014-2127",		# Cisco ASA privilege escalation vuln
				#"http-vuln-cve2014-2128",		# Cisco ASA privilege escalation vuln 
				#"http-vuln-cve2014-2129",		# Cisco ASA privilege escalation vuln 
				#"http-vuln-cve2014-3704",		# SQL Injecection for Drupal
				#"http-vuln-cve2014-8877",		# Remote code injection for Wordpress 
				#"http-vuln-cve2015-1427",		# Remote code execution via API exploitation 
				#"http-vuln-cve2015-1635",		# Remote code execution on Microsoft systems 
				#"http-vuln-cve2017-1001000",	# Privilege escalation on Wordpress 
				#"http-vuln-cve2017-5638",		# Remote code execution for Apache Struts 
				#"http-vuln-cve2017-5689",		# Pivilege escaltion for Intel Active management 
				#"http-vuln-cve2017-8917",		# SQL injection for Joomla
				#"http-vuln-misfortune-cookie",	# RomPager Cookie vuln 
				#"http-vuln-wnr1000-creds",		# Admin creds steal from WMR 1000 series 
				#"http-adobe-coldfusion-apsa1301", # Auth bypass via adobe coldfusion 
				#"http-affiliate-id", 			# grabs affiliate network information 
				#"http-apache-negotiation",		# enables mod_negociation,allows potential spidering 
				#"http-apache-server-status",	# attempts to retrieve apache server information 
				#"http-aspnet-debug",			# determines if service enabled aspnet debug mode 
				#"http-auth",					# get authentication scheme 
				#"http-auth-finder",				# spiders for getting http based auth 
				#"http-awstatstotals-exec", 		# remote code execution in Awstats total 
				#"http-axis2-dir-traversal",		# directory traversal in for apache axis2 
				#"http-backup-finder",			# spidering attempt to discover duplicates/backup files 
				#"http-brute",					# basic brute force http auth attack 
				#"http-chrono",					# times page's responsivness 
				#"http-cisco-anyconnect",		# connects as cisco AnyClient and retrieves basic information 
				#"http-coldfusion-subzero",		# admin creds steal vial coldfusion vuln 
				#"http-comments-displayer",		# displays comments from pages 
				#"http-config-backup",			# searches for duplicates of system/server setup files 
				#"http-cors",					# tests for cross-origin resource sharing 
				#"http-cross-domain-policy",		# checks cross domain policy to expose overly permissive forms 
				#"http-csrf",					# detects csrf forgeries 
				#"http-default-accounts",		# tests for default accounts that may exist 
				#"http-dlink-backdoor",			# checks for a firmware vuln on some dlink routers 
				#"http-dombased-xss",			# uses the dom to leverage javascript 
				#"http-domino-enum-passwords",	# tries to use the hashed Domino passwords 
				#"http-feed",					# tries to get any rss information that may be present 
				#"http-form-brute",				# brute forces http form based authentication 
				#"http-generator",				# display's contents of generator metatab 
				#"http-headers",					# tries to get a head request for "/" 
				#"http-joomla-brute",			# brute force attack against joomla web CMS installations 
				#"http-malware-host",			# signature search for known compromises 
				#"http-proxy-brute",
				#"http-sql-injection",
				"http-methods"					# gets available methods from service (we only care about this for now)
			]
		else:
			for i in scripts_to_run:
				self.__valid_scripts.append(i)

	def run(self):
		results = self.nm.scan(self.target, arguments=self.port_values+" --script "+" --script ".join(self.__valid_scripts))

		return list(find(results))

