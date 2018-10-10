#!/usr/bin/python3

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

import os
import sys
import time

if(sys.version_info[0] < 3):
	print("Please run ADAPT in python 3")
	sys.exit()

if(not os.path.isfile("./var/adapt_installed") or 
	not os.path.isdir("./lib/testssl.sh") or
	not os.path.isdir("./var/SecLists")):
	import subprocess
	print("It seems that you have not run the installer script.")
	print("We will now run that briefly before continuing.")
	subprocess.call(["./install.sh"])
	

sys.path.insert(0, os.getcwd()+"/src")
sys.path.insert(0, os.getcwd()+"/var")
sys.path.insert(0, os.getcwd()+"/bin")
sys.path.insert(0, os.getcwd()+"/lib")
sys.path.insert(0, os.getcwd()+"/etc")

import json, argparse, threading, paramiko, adapt_config_parser
from zap_interface import AdaptZap
from owasp_suite import owasp_suite
from adapt_analysis import adapt_analysis
from aprint import aprint
import getpass

if(not os.path.isfile("./var/adapt_installed") or not os.path.isdir("./lib/testssl.sh")):
	print("It seems like you have not run the installer script")

# This parses the main configuration file and returns its 
# location so we don't have as many hard coded location
main_config_file = adapt_config_parser.parse()
with open(main_config_file) as temp:
	temp_args = json.load(temp)
printer = aprint(temp_args["adapt_general"]["verbose"], "adapt_main")
temp.close()

class PenTester():
	def __init__(self, args):
		self.args = args
		printer.aprint("Test bed setup done")
		self.successful = False

	def run(self):
		return self.start_penetration_testing()
	def start_penetration_testing(self):
		printer.aprint(self.args["adapt_general"]["target_name"])
		if(self.args["adapt_general"]["target_name"] is None):
			# This basically means everything failed
			return {}

		printer.aprint("Initializing zap")
		zapper = AdaptZap(self.args)
		printer.aprint("Zap initialized")
		
		printer.aprint("Checking for authorization availability...")
		if(zapper.auth_success):
			printer.aprint("Authorization is available!")
		else:
			self.args["adapt_general"]["skip_authentication"] = True
			for i in self.args["owasp_general"]["tests_that_require_login"]:
				self.args["owasp_general"]["tests_to_run"][i] = False
		
		# Try to spider
		#try:
		printer.aprint("Zap spider starting...")
		if(self.args["zap_general"]["spider_turned_on"]):
			zapper.spider()
		printer.aprint("DONE")
		#except Exception as e:
		#	printer.aprint("FAILED: "+str(e))

		# Try to pscan
		try:
			printer.aprint("Zap pscan starting... ")
			if(self.args["zap_general"]["pscan_turned_on"]):
				zapper.pscan()
			printer.aprint("DONE")
		except Exception as e:
			printer.aprint("FAILED: "+str(e))

		# Try to ascan
		try:
			printer.aprint("Zap ascan starting...")
			if(self.args["zap_general"]["ascan_turned_on"]):
				zapper.ascan()
			printer.aprint("DONE")
		except Exception as e:
			printer.aprint("FAILED: "+str(e))

		try:
			printer.aprint("Pulling results from zap")
			self.zap_results = zapper.get_results()
		except:
			self.zap_results = {
				"alerts":[],
				"sites":[],
				"urls":[],
				"hosts":[]
			}

		printer.aprint("Initializing owasp suite")
		owasp = owasp_suite(self.args, zapper)
		printer.aprint("Owasp initialized")
		printer.aprint("Running suite")
		self.owasp_results = owasp.run()
		printer.aprint("Done running suite")
		printer.aprint("Done scanning")
		self.successful = True

def bool_argparse(v):
	if v is None:
		return None
	if str(v).lower() in ('yes', 'true', 't', 'y', '1'):
		return True
	elif str(v).lower() in ('no', 'false', 'f', 'n', '0'):
		return False
	else:
		raise argparse.ArgumentTypeError('Boolean value expected')

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("--target", type=str, help="Attack target specification", default=os.environ.get('ADAPT_TARGET'))
	parser.add_argument("--context", type=str, help="Attack context specification", default=os.environ.get('ADAPT_CONTEXT'))
	parser.add_argument("--verbose", type=bool, nargs='?', help="Turns on verbose")
	parser.add_argument("--output", type=str, help="Output file specification", default=os.environ.get('ADAPT_OUTPUT'))
	parser.add_argument("--append", type=str, help="Append data to output file.", default=os.environ.get('ADAPT_APPEND'))
	parser.add_argument("--risk", type=str, help="Risk value specification: [low, medium, high, paranoid]", default=os.environ.get('ADAPT_RISK'))
	parser.add_argument("--conf", type=str, help="Confidence value specification: [low, medium, high, paranoid]", default=os.environ.get('ADAPT_CONF'))
	parser.add_argument("--detail", type=str, help="Specification for analysis detail: [low, medium, high, full]", default=os.environ.get('ADAPT_DETAIL'))
	parser.add_argument("--skip_authentication", type=bool_argparse, default=bool_argparse(os.environ.get('ADAPT_SKIP_AUTHENTICATION')), help="True to skip authentication or False to perform authentication")

	args = parser.parse_args()
	return args

def __unsupported_value(label, value, correct):
	print("Unsupported "+label+" value: "+value)
	print("Please use any from: "+str(correct))
	sys.exit(1)

def ssh_capture_dmesg_logs(args):
	printer.aprint("Getting ssh logs")
	hostname = args["ssh_config"]["hostname"]
	port = args["ssh_config"]["port"]
	username = args["ssh_config"]["username"]
	password = args["ssh_config"]["password"]

	printer.aprint("Connecting...")
	try:	
		client = paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	except Exception as e:
		printer.aprint("ERROR: "+str(e), 2)

	connection_attempts = 1
	connection_success = False

	ssh_connection_timeout = 30
	exception_reason = None

	# now tries to connect 3 times before fully failing. 
	# increases banner, auth and general timeout after each failure
	while(connection_attempts < 4):
		printer.aprint("Attempt "+str(connection_attempts)+"/3 ... ")
		try:
			client.connect(
				hostname=hostname,
				username=username,
				password=password,
				port=port,
				banner_timeout=ssh_connection_timeout,
				auth_timeout=ssh_connection_timeout,
				timeout=ssh_connection_timeout
			)
			ftp_client = client.open_sftp()
			connection_success = True
			printer.aprint("Connected!")
			break
		except Exception as e:
			printer.aprint("Attempt "+str(connection_attempts)+" failed: "+str(e))
			time.sleep(30)
			ssh_connection_timeout+=60
			exception_reason = e
		connection_attempts += 1

	if(not connection_success):
		raise Exception("Cannot connect to ssh server: "+str(exception_reason))

	printer.aprint("Getting files...")
	for i in args["ssh_config"]["log_paths"]:

		filename = ""

		log_path = i
		if(log_path == "apache2"):
			log_path = "/var/log/http-error.log"
			filename = "http-error.log"
		elif(log_path == "php"):
			log_path = "/var/log/php-scripts.log"
			filename = "php-scripts.log"
		elif("." not in log_path.split("/")[-1]):
			continue
		else:
			filename = log_path.split("/")[-1]

		try:
			ftp_client.get(log_path, "./tmp/"+filename)
		except:
			printer.aprint("SSH ERROR: cannot get file at location: "+log_path, 2)
	printer.aprint("Done")
	
	try:
		printer.aprint("Closing...")
		ftp_client.close()
		client.close()
	except:
		pass

def main():
	printer.aprint("Loading config file")
	with open(main_config_file) as datafile:
		args = json.load(datafile)
	datafile.close()

	supported_file_formats = ["json", "xml", "stdout"]
	supported_risk_conf_values = ["low", "medium", "high", "paranoid"]
	supported_analysis_detail = ["low", "medium", "high", "full", "owasp10"]

	printer.aprint("Checking command line args and environment variables")
	command_line_args = get_args()
	if(command_line_args.target != None):
		args["adapt_general"]["target_name"] = command_line_args.target
	if(command_line_args.verbose):
		args["adapt_general"]["verbose"] = True
	if(command_line_args.output != None):
		args["adapt_general"]["output_file"] = command_line_args.output
		# get the filetype for the output file 
		args["output_format"] = command_line_args.output.split(".")[-1]
		if(args["adapt_general"]["output_format"] not in supported_file_formats):
			__unsupported_value("output file format", args["adapt_general"]["output_format"], supported_file_formats)
	if(command_line_args.append != None):
		args["adapt_general"]["output_file"] = command_line_args.append
		args["adapt_general"]["output_format"] = command_line_args.append.split(".")[-1]
		if(args["adapt_general"]["output_format"] not in supported_file_formats):
			__unsupported_value("output file format", args["adapt_general"]["output_format"], supported_file_formats)

	if(command_line_args.conf != None):
		if(command_line_args.conf not in supported_risk_conf_values):
			__unsupported_value("conf", command_line_args.conf, supported_risk_conf_values)
		args["adapt_general"]["analysis_confidence_sensitivity"] = command_line_args.conf

	if(command_line_args.risk != None):
		if(command_line_args.risk not in supported_risk_conf_values):
			__unsupported_value("risk", command_line_args.risk, supported_risk_conf_values)
		args["adapt_general"]["analysis_risk_sensitivity"] = command_line_args.risk

	if(command_line_args.detail != None):
		if(command_line_args.detail not in supported_analysis_detail):
			__unsupported_value("analysis detail", command_line_args.detail, supported_analysis_detail)
		args["adapt_general"]["analysis_detail"] = command_line_args.detail

	if command_line_args.context is not None:
		args["adapt_general"]["context_name"] = command_line_args.context

	if command_line_args.skip_authentication is not None:
		args["adapt_general"]["skip_authentication"] = command_line_args.skip_authentication

	if(len(sys.argv) > 1):
		sys.argv = [sys.argv[0]]

	printer.aprint("Final config setup...")

	if(args["zap_general"]["hidden"]):
		args["zap_general"]["opts"].append("-daemon")

	if(not args["adapt_general"]["skip_authentication"]):
		if(args["adapt_general"]["username"] == "//stdin"):
			args["adapt_general"]["username"] = getpass.getpass("Valid service username:")

		if(args["adapt_general"]["password"] == "//stdin"):
			args["adapt_general"]["password"] = getpass.getpass("Valid service password:")

	if(args["ssh_config"]["turned_on"]):
		if(args["ssh_config"]["username"] == "//stdin"):
			args["ssh_config"]["username"] = getpass.getpass("SSH username:")

		if(args["ssh_config"]["password"] == "//stdin"):
			args["ssh_config"]["password"] = getpass.getpass("SSH password:")

	printer.aprint("... Done")

	printer.aprint("Test bed setup starting...")
	pentester = PenTester(args)
	pentester.run()
	printer.aprint("Test bed finished")
	if( pentester.successful ):
		if(args["ssh_config"]["turned_on"]):
			ssh_capture_dmesg_logs(args)
	
		analysis = adapt_analysis( pentester.zap_results, pentester.owasp_results,args=args)
		analysis.get_results()

	for i in os.listdir("./tmp/"):
		os.remove("./tmp/"+i)

	return None

if(__name__ == "__main__"):
	main()

