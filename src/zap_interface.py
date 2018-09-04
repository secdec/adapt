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

import os, sys, time, datetime, logging, subprocess, json, html, urllib, re, importlib
#from httpparser.httprequest import HTTPRequest
from zapv2 import ZAPv2
from aprint import aprint
import progressbar

class AdaptZap():
	def __init__(self, args):
		self.args = args
		self.printer = aprint(self.args["adapt_general"]["verbose"], "zap_interface")

		self.host = self.args["zap_general"]["host"]
		self.port = self.args["zap_general"]["port"]
		self.api_key = self.args["zap_general"]["api_key"]
		if(self.api_key is None):
			self.api_key = self.gen_random_api_key()

		self.zap_path = self.args["zap_general"]["path"]
		self.zap_opts = self.args["zap_general"]["opts"]
		self.close_on_finish = self.args["zap_general"]["close_on_finish"]
		self.target = self.args["adapt_general"]["target_name"]
		self.context = self.args["adapt_general"]["context_name"]

		self.already_connected = False
		self.already_opened = False

		# this is the spearate zap process 
		self.p = None

		self.context_name = "ADAPT Context"
		self.session_counter = 0
		self.spiderid = None

		if(not self.open()):
			raise Exception("Could not open zap")
		if(not self.connect()):
			raise Exception("Unable to establish zap proxy")

		self.contextid = self.__setup_context(self.args["zap_general"]["excluded"], self.context_name)

		# Attempt to use login function as test of verified ability 
		try:
			#self.auth_module.service_auth(self.args["adapt_general"]["username"], self.args["adapt_general"]["password"])
			self.auth_module = importlib.import_module(self.args["adapt_general"]["auth_module"][:-3])
			self.create_new_session(self.args["adapt_general"]["username"], self.args["adapt_general"]["password"])
			self.auth_success = True
			self.printer.aprint("Authentication succeeded")
		except Exception as e:
			self.printer.aprint("Authentication failed: "+str(e), 1)
			self.auth_success = False

		self.printer.aprint("Finished setup")

	def get_results(self):
		return {
			"hosts":self.zap.core.hosts,
			"sites":self.zap.core.sites,
			"urls":self.zap.core.urls(),
			"alerts":self.zap.core.alerts()
		}

	def spider_messages(self):
		in_scope_results = self.zap.spider.full_results(self.spiderid)[0]['urlsInScope']
		messages = []
		for res in in_scope_results:
			messages.append(self.zap.core.message(id=res["messageId"]))
		return messages

	def spider_urls(self):
		return self.zap.spider.full_results(self.spiderid)[0]["urlsInScope"]

	def send_request(self, request):
		resp = self.zap.core.send_request(request)
		if( not isinstance(resp, list) or not isinstance(resp[0], dict)):
			raise Exception("Request {} failed during test_logins. Expected zap message, got: {}".format(request, resp))
		return resp[0]

	def create_new_session(self, username, password):
		new_sess = self.get_session(username, password)[0]
		return chain_zap_ops([
			lambda:self.zap.forcedUser.set_forced_user_mode_enabled(False),
			lambda:self.zap.httpsessions.set_active_session(self.target, new_sess)
		])

	def gen_random_api_key(self):
		from string import ascii_letters,digits
		from random import choice 
		char_pool = ascii_letters + digits
		return ''.join(choice(char_pool)for i in range(20))

	def __sess_val(self):
		self.session_counter+=1
		return "session"+str(self.session_counter)

	def test_login(self, username, password, uid_name="test_logins"):
		return self.auth_module.service_auth(username, password)

	def get_session(self, username, password):
		for i in range(0,3):
			preexisting_sessions = self.zap.httpsessions.sessions(self.target)
			login_msg = self.test_login(username, password)
			if(login_msg == None):
				raise Exception("Error in authentication")
			if(login_msg["successful"] == True):
				new_sess = self.__sess_val()
				self.zap.httpsessions.create_empty_session(self.target, new_sess)
				for key,value in login_msg["cookies"].items():
					self.zap.httpsessions.add_session_token(self.target, key)
					self.zap.httpsessions.set_session_token_value(self.target, new_sess, key, value)
				new_sessions = self.zap.httpsessions.sessions(self.target)
				assert(len(preexisting_sessions) == len(new_sessions)-1)
				return (new_sess, new_sessions[-1]['session'])
			raise Exception("Cannot authenticate after 3 attempts, either login script is incorrect or ZAP has changed this user's password in the database.")

	def __del__(self):
		self.close()

	def close(self):
		self.already_connected = False
		self.already_opened = False
		if(self.p is not None and self.close_on_finish):
			self.p.kill()
			self.p.wait()

	def __setup_context(self, excluded_paths, context_name):
		contextid = self.zap.context.new_context(context_name)
		self.zap.context.include_in_context(context_name, self.context+".*")
		for e in excluded_paths:
			self.printer.aprint("Excluded path: {}".format(e))
			self.zap.context.exclude_from_context(context_name, "{}{}".format(self.context,e))
		return contextid

	def open(self):
		self.printer.aprint("open zap daemon "+str(self.zap_path))
		zap_execve = "exec {} {} -config api.key={} -port {}".format(
			self.zap_path,
			' '.join(self.zap_opts),
			self.api_key,
			self.port
		)
		self.p = subprocess.Popen(zap_execve, stdout=open(os.devnull, "w"), shell=True)
		self.printer.aprint("Waiting for zap startup... ")
		bar = progressbar.ProgressBar(maxval=60, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
		if(self.args["adapt_general"]["verbose"]):bar.start()
		for i in range(60):
			if(self.args["adapt_general"]["verbose"]):bar.update(i)
			time.sleep(1)
		if(i < 59):
			self.printer.aprint("CANNOT LOAD ZAP. PLEASE CHECK FOR ZAP UPDATES.", c=2)
			sys.exit(1)
		if(self.args["adapt_general"]["verbose"]):bar.finish()
		self.printer.aprint("DONE")
		self.already_opened = True
		return True

	def connect(self):
		px = {"http":self.host+":"+self.port, "https":self.host+":"+self.port}
		self.printer.aprint("Connecting to zap... ")
		self.zap = ZAPv2(apikey=self.api_key, proxies=px)
		self.printer.aprint("Opening url")
		self.zap.urlopen(self.target, timeout=5)
		self.already_connected = True
		return True

	def check(self):
		assert(self.already_opened)
		assert(self.already_connected)

	def spider(self):
		self.printer.aprint("Spider start")
		self.check()
		self.printer.aprint(self.context_name)
		scanid = self.zap.spider.scan(self.target, contextname=self.context_name)

		if("not in the required context" in scanid):
			pass
		self.spiderid = scanid

		self.printer.aprint("scanid: "+str(scanid))

		bar = progressbar.ProgressBar(maxval=100, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])

		if(self.args["adapt_general"]["verbose"]):bar.start()
		while(True):
			scan_progress = int(self.zap.spider.status(scanid))
			if(self.args["adapt_general"]["verbose"]):bar.update(scan_progress)
			if(scan_progress >= 100):
				break
			time.sleep(1)
		if(self.args["adapt_general"]["verbose"]):bar.finish()
		self.printer.aprint("Spider done")

	def pscan(self):
		self.printer.aprint("Pscan start")
		self.check()
		bar = progressbar.ProgressBar(maxval=100, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
		self.printer.aprint("This could take a while. Please be patient.")
		if(self.args["adapt_general"]["verbose"]):bar.start()
		total = int(self.zap.pscan.records_to_scan)
		while(int(self.zap.pscan.records_to_scan) > 0):
			if(self.args["adapt_general"]["verbose"]):bar.update(int(self.zap.pscan.records_to_scan)/total)
			time.sleep(1)
		if(self.args["adapt_general"]["verbose"]):bar.finish()
		self.printer.aprint("Pscan done")

	def ascan(self):
		self.printer.aprint("Ascan start")
		self.check()
		scanid = self.zap.ascan.scan(contextid=self.contextid)
		bar = progressbar.ProgressBar(maxval=100, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
		if(self.args["adapt_general"]["verbose"]):bar.start()
		while(True):
			scan_progress = int(self.zap.ascan.status(scanid))
			if(self.args["adapt_general"]["verbose"]):bar.update(scan_progress)
			if(scan_progress >= 100):
				break
			time.sleep(2)
		if(self.args["adapt_general"]["verbose"]):bar.finish()
		self.printer.aprint("Ascan done")

def chain_zap_ops(lof):
	for f in lof:
		res = f()
		if(res != "OK"):
			return res
	return res

