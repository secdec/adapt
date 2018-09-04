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

# File: login_format.py
# ADAPT

import requests
from pprint import pprint
from bs4 import BeautifulSoup as soup
import re, time

# NOTE that this is just an example file for authentication for DVWA. 
# 
# In order to use ADAPT fully, authentication scripts are needed to sign into 
# the applications. To allow authentication for ADAPT you must write your own
# python script to authenticate the service you want to test. This file is a
# complete example for DVWA. 
#

# REQUIREMENTS: 
# FUNCTION : The function name must be called 'service_auth'. The file may be called 
# anyhting but ADAPT will utilize the function service_auth. If it does 
# not exist, it will not run some tests. 
#
# PARAMETERS : Service auth must take two parameters. It can take more, 
# The username as the first parameter and a password as the second parameter. 
# It is up the user to create a function to user these to create a new login 
# session that ADAPT is looking for. 
#
# RETURN VALUE : service_auth must return a python dictionary type with specific 
# keys present. 
# Required keys:
#	responseHeader (str)
#	 - This is the header from the responding of making the POST request		
#	responseBody (str)
#	 - This is the body from the responding POST request 
#	requestHeader (str)
#	 - This is the header of the POST request 
#	requestBody (str)
#	 - This is the body of the POST request 
#	cookies (dict -> {str : str})
#	 - These are the cookies and sessionid values that are returned 
#	rtt (float)
#	 - round trip time of the request in milliseconds. 
#	successful (bool)
#	 - If the login of the given username/password was successful in logging in

# For custom login scripts, the authentication can be very simple. Such as a single
# POST request. 
# In this example however, we do scan for a csrf token in the DVWA login page. 

# Here is the dvwa example login script. 
def service_auth(username, password):

	# Setting up the post data information 
	payload = {"username":username, "password":password, "Login":"Login"}

	# This is the login url we are going to post to
	login_url = "http://localhost/login.php"

	# Create a requests session for csrf token information 
	client = requests.session()

	# Starting off as unsuccessful
	successful = False

	# GET the login url 
	dvwa_get = client.get(login_url, allow_redirects=False)

	# begin parsing of the GET request 
	s = soup(dvwa_get.text)

	# Search for the csrf token input on DVWA's login page 
	user_token = s("input", {"name":"user_token"})[0]["value"]

	# Get the session id out of the headers 
	session_id = re.match("PHPSESSID=(.*?);", dvwa_get.headers["set-cookie"]).group(1)

	# Initialize timer for login 
	rtt = time.time()

	# Set user_token into data payload 
	payload["user_token"] = user_token

	# Set final cookie information 
	cookie = {"PHPSESSID":session_id, "security":"low"}

	# Make login POST request 
	dvwa_post = client.post(login_url, data=payload, cookies=cookie, allow_redirects=True)

	# Get updated time 
	rtt = time.time()-rtt

	# Make Sure the request values are not empty and return strings 
	request_headers = ""
	for key,val in dvwa_post.request.headers.items():
		request_headers+= key+": "+val+"\r\n"

	# Make sure the request values are not empty and return strings 
	request_body = ""
	if(dvwa_post.request.body != None):
		request_body = dvwa_post.request.body

	# Make sure the response headers are one string
	response_headers = ""
	for key,val in dvwa_post.headers.items():
		response_headers+=key+": "+val+"\r\n"

	# Check for unique string on login page if failed login 
	# (This will be unique for pretty much every web service)
	if("Login failed" not in dvwa_post.text):
		successful = True

	# Return dictionary 
	return {
		"responseHeader":response_headers, 
		"requestHeader":request_headers, 
		"requestBody":request_body, 
		"successful":successful, 
		"cookies":cookie, 
		"rtt":rtt, 
		"responseBody":dvwa_post.text
	}

if(__name__ == "__main__"):
	pprint(service_auth("admin", "password"))
