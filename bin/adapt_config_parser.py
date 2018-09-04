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

import json 
import sys
import os
import configparser
import socket
from contextlib import closing
from urllib.parse import urlencode, urlsplit, parse_qs

# This file edits the file configuration.json to use the correct paths 
# during the installation process. This is done in python because its 
# easier than treating the file as a string. 

risk_conf = {"low", "medium", "high", "paranoid"}
detail = {"low", "medium", "high", "full"}

files = {"json", "xml", "stdout"}

on_off = {"on":True, "off":False}

def config_error(val):
	print(val)
	print("Quitting")
	sys.exit()

def set_get(val, s, e):
	if(val in s):
		return val
	return e

def onf(val, e=False):
	return on_off.get(val.lower(), e)

def noner(val, s):
	if(val in s):
		return val
	return None

# takes a string of numbers and throws out any non numbers
def number_list_verification(l, config_loc):
	number_list = l.split()
	final = []
	for i in number_list:
		try:
			int(i)
			final.append(i)
		except:
			config_error(i+" is not an integer in "+config_loc)
	final = " ".join(final)
	return final

def get_config_defaults(contents):
	parser = configparser.ConfigParser()
	x = open(os.getcwd()+"/adapt.config")
	y = x.read()
	x.close()
	a = ""
	for i in y:
		if(i == "%"):
			a+="%%"
		else:
			a+=i
	if("tmp" not in os.listdir()):
		os.mkdir(os.getcwd()+"/tmp")
	x = open(os.getcwd()+"/tmp/adapt.config", "w")
	x.write(a)
	x.close()
	parser.read(os.getcwd()+"/tmp/adapt.config")

	ast_op = parser["GENERAL_OPTIONS"]
	out_op = parser["OUTPUT_OPTIONS"]
	ssh_op = parser["SSH_OPTIONS"]
	zap_op = parser["OWASP_ZAP_OPTIONS"]
	owa_op = parser["OWASP_OPTIONS"]
	dbg_op = parser["DEBUG_OPTIONS"]
	ath_op = parser["AUTH_OPTIONS"]

	# ADAPT options 
	contents["adapt_general"]["analysis_confidence_sensitivity"] = set_get(ast_op["confidence"], risk_conf, "medium")
	contents["adapt_general"]["analysis_risk_sensitivity"] = set_get(ast_op["risk"], risk_conf,"medium")
	contents["adapt_general"]["analysis_detail"] = set_get(ast_op["detail"], detail, "medium")
	contents["adapt_general"]["target_name"] = ast_op["target"]
	contents["adapt_general"]["context_name"] = ast_op["context"]
	if(ast_op["nmap_script_ports"] == "default"):
		# default to just 80 to make things faster 
		contents["adapt_general"]["nmap_script_ports"] = "80"
	elif(ast_op["nmap_script_ports"] == "all"):
		contents["adapt_general"]["nmap_script_ports"] = None
	elif(ast_op["nmap_script_ports"] == "skip"):
		contents["adapt_general"]["nmap_script_ports"] = "skip"
	else:
		contents["adapt_general"]["nmap_script_ports"] = number_list_verification(ast_op["nmap_script_ports"], "nmap script ports")

	# Output options 
	if(out_op["specific_filename"] == "none"):
		contents["adapt_general"]["output_file"] = None
	else:
		contents["adapt_general"]["output_file"] = out_op["specific_filename"]
	contents["adapt_general"]["output_format"] = set_get(out_op["filetype"], files, "json")
	contents["adapt_general"]["append"] = onf(out_op["append"])

	# SSH options
	contents["ssh_config"]["turned_on"] = onf(ssh_op["ssh_get_logs"])
	contents["ssh_config"]["hostname"] = ssh_op["hostname"]
	contents["ssh_config"]["username"] = ssh_op["username"]
	try:
		contents["ssh_config"]["port"] = str(int(ssh_op["port"]))
	except:
		config_error("SSH port is not an integer")
	contents["ssh_config"]["password"] = ssh_op["password"]
	contents["ssh_config"]["log_paths"] = ssh_op["log_paths"].split()
	contents["ssh_config"]["read_direction"] = set_get(ssh_op["read_direction"], ["full", "bottom", "top"], "full")
	try:
		contents["ssh_config"]["read_amount"] = str(int(ssh_op["read_amount"]))
	except:
		config_error("SSH read amount is not an integer")
	if(len(contents["ssh_config"]["log_paths"]) == 0):
		contents["ssh_config"]["turned_on"] = False
	if(ssh_op["keywords"] == "none" or len(ssh_op["keywords"]) == 0):
		contents["ssh_config"]["keywords"] = ["WARNING", "warning", "ERROR", "error"]
	else:
		contents["ssh_config"]["keywords"] = ssh_op["keywords"].split()

	# ZAP options
	contents["zap_general"]["pscan_turned_on"] = onf(zap_op["passive_scan"])
	contents["zap_general"]["ascan_turned_on"] = onf(zap_op["active_scan"])
	contents["zap_general"]["spider_turned_on"] = onf(zap_op["spider_scan"])
	if(zap_op["api_key"] == "none"):
		contents["zap_general"]["api_key"] = None
	else:
		contents["zap_general"]["api_key"] = zap_op["api_key"]
	#contents["zap_general"]["port"] = zap_op["zap_port"]
	contents["zap_general"]["excluded"] = zap_op["exclude"].split()

	# OWASP options
	for i in owa_op:
		contents["owasp_general"]["tests_to_run"][i] = onf(owa_op[i])

	# gray box options 
	contents["adapt_general"]["verbose"] = onf(dbg_op["adapt_verbose"])
	contents["zap_general"]["close_on_finish"] = onf(dbg_op["zap_close"])
	contents["zap_general"]["hidden"] = onf(dbg_op["zap_hidden"])
	if(contents["zap_general"]["hidden"] == True):
		contents["zap_general"]["close_on_finish"] = True

	auth_module = ath_op["auth_module"]
	contents["adapt_general"]["username"] = ath_op["valid_username"]
	contents["adapt_general"]["password"] = ath_op["valid_password"]
	if(len(auth_module) < 3):
		contents["adapt_general"]["skip_authentication"] = True
		contents["adapt_general"]["auth_module"] = None
	elif(auth_module[-3:] == ".py"):
		contents["adapt_general"]["skip_authentication"] = False
		contents["adapt_general"]["auth_module"] = auth_module
	else:
		contents["adapt_general"]["skip_authentication"] = True
		contents["adapt_general"]["auth_module"] = None

	if(contents["adapt_general"]["skip_authentication"] == True):
		for i in contents["owasp_general"]["tests_that_require_login"]:
			contents["owasp_general"]["tests_to_run"][i] = False

	# we have to check if the service is running out of the same port 
	#if( contents["adapt_general"]["target_name"].startswith("http://localhost:"+contents["zap_general"]["port"]) or 
	#	contents["adapt_general"]["target_name"].startswith("https://localhost:"+contents["zap_general"]["port"]) or
	#	contents["adapt_general"]["target_name"].startswith("http://127.0.0.1:"+contents["zap_general"]["port"]) or
	#	contents["adapt_general"]["target_name"].startswith("https://127.0.0.1:"+contents["zap_general"]["port"])):
	p = ""

	while(True):
		sock = socket.socket()
		sock.bind(('', 0))
		try:
			p = str(sock.getsockname()[1])
			sock.close()
			if(p != "80"):
				break
		except:
			print("Could not find available port for zap.")
			sys.exit()
	contents["zap_general"]["port"] = p

	return contents

def parse():
	filename = os.getcwd()+"/var/configuration.json"
	current_path = os.getcwd()
	with open(filename) as datafile:
		contents = json.load(datafile)
		datafile.close()

	contents = get_config_defaults(contents)

	for i in range(len(contents["zap_general"]["opts"])):
		if(contents["zap_general"]["opts"][i] == "-dir"):
			contents["zap_general"]["opts"][i+1] = current_path+"/zap"
		if(contents["zap_general"]["opts"][i] == "-config" and contents["zap_general"]["opts"][i+1].startswith("dirs=")):
			contents["zap_general"]["opts"][i+1] = "dirs="+current_path+"/zap/scripts"

	with open(filename, "w") as f:
		json.dump(contents, f, indent=4, sort_keys=True)
		f.close()

	return filename

