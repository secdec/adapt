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

'''
----------------------------------
ADAPT ERROR GENERATING TEST CASES
----------------------------------
This python module is attempt to address the OTG-ERR-002 requirements defined in the OWASP Testing Guide.
Below are the general points in this penetration testing:
        1) Use Zap scans messages and URLs
        2) Run a suite of test cases on these urls with invalid input to try to cause an exception and/or stack trace
        returned back to the client.

The goal of this penetration testing is create an exception on the backend services so we can try to do stack analysis to
determine specific details about the application.
'''
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import requests
import re
from httpparser.httprequest import HTTPRequest
import progressbar

class error_suite():
	#
	# Constructor
	#
	def __init__(self, args, zapper):
		self.zapper = zapper
		urlList = zapper.zap.core.urls()
		self.urlList = urlList
		self.args = args

	#
	# Method to iterate over the Zap msgs to try to product exceptions via invalid input and SQL injections
	#	
	def attack_url_via_get1_v2( self, ref_zapmsg ):
		report_list = []
		ref_request = HTTPRequest.read( ref_zapmsg['requestHeader'] + ref_zapmsg['requestBody'] )
		ref_response = ref_zapmsg['responseHeader'] + str(ref_zapmsg['responseBody'])
		get1_attacks = [ "A"*2048, "" ]
		sqlInjectList = self.build_sql_injections()
		get1_attacks += sqlInjectList
		req_copy = ref_request.copy()
		for k,ref_val in req_copy.path_params.items():
			if( ref_val is None ):
				pass
			for atk in get1_attacks :
				req_copy.path_params[k] = atk
				req1 = req_copy.write()
				resp = self.zapper.send_request( req1 )
				respHeader = resp['responseHeader']
				headers = respHeader.split()
				status = headers[1]
				respCode = headers[2]
				statusCode = int(status)
				# if the request returns a 400 or above and the response contains the keyword 'exception', lets report it so we can do analysis on the
				# stack trace that was produced
				if ( statusCode >= 400 ):
					responseBody = str(resp['responseBody'])
					if re.search('exception|error', responseBody, re.IGNORECASE):
						from owasp_suite import create_report
						report = create_report("err_002", "Found exception in HTTP response", "medium", req1 , 1.0, responseBody, owasp_association="6")
						report_list.append( report )
		return report_list


	#
	# This method attacks URL via HTTP POST with invalid inputs and basic SQL injections
	#
	def attack_url_via_post(self, url, formdata=None):
		invalidInputs = [ "alsdfjhashdkajdhjkahdash322343242342&lk3j24lk234j2l34j&lj23l4jl2k3j4l2j4j2l;4jl;2fgkjldfjglkldhfqmnrejqwkjehkqwehrkqhekqwheklhqwekjhqwkheklqwhelkhqwehqwkehqwhekqhweklqwejhqwlkehkqwhe", ""]
		sqlInjections = self.build_sql_injections()

		# invalid input
		for inv in invalidInputs:
			for key, value in formdata.items():
				if value is None or value == "":
					formdata[key] = inv
					resp = requests.post(url, data=formdata)
		# sql injections
		for sql in sqlInjections:
			for key, value in formdata.items():
				if value is None or value == "":
					formdata[key] = sql
					resp = requests.post(url, data=formdata)

	#
	# Build basic SQL innjection list	
	#
	def build_sql_injections(self):
		l = [ "' OR '1'='1' --", "\' OR\'1\'=\'1\' --", "' OR '1'='1' ({", "' OR '1'='1' /*", "' AND 1=2'", "1 or x=1", "\' OR x=1", "\' union select 1" ]
		return l

	#
	# This method searches html page for HTML form tags
	#
	def check_for_html_form(self, hostname, url):
		fullUrl = "{0}/{1}".format(hostname, url)
		if fullUrl != None and "http://" in fullUrl:
			r = requests.get(fullUrl)
			html = r.text
			soup = BeautifulSoup(html, 'lxml')
			for f in soup.find_all('form'):
				if (f is not None):
					method = f.get('method')
					action = f.get('action')
					# fields = f.findAll('input', recursive=False)
					fields = f.findAll('input')
					formdata = dict((field.get('name'), field.get('value')) for field in fields)
					self.attack_url_via_post(fullUrl, formdata)

	def run(self):
		report_list = []
		if self.zapper.spider_messages() != None:
			bar = progressbar.ProgressBar(maxval=len(self.zapper.spider_messages()), widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
			if(self.args["adapt_general"]["verbose"]):bar.start()
			#for zapmsg in self.zapper.spider_messages():
			messages = self.zapper.spider_messages()
			for i in range(len(messages)):
				if(self.args["adapt_general"]["verbose"]):bar.update(i)
				zapmsg = messages[i]
				requestHeader = zapmsg["requestHeader"]
				headers = requestHeader.split()
				method = headers[0]
				url = headers[1]
				reports = self.attack_url_via_get1_v2( zapmsg )
				if (reports):
					report_list += reports
			if(self.args["adapt_general"]["verbose"]):bar.finish()

		return report_list

