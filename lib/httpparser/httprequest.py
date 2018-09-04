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

import itertools
from copy import deepcopy
import urllib.parse

'''
HTTPRequest class

The purpose of this class is to serve as a common interface for parsing and modifiyng http requests
Given a raw http request, this class will parse it into different components, allowing the user
to make changes, then write the modified request back out.

Sample workflow looks like this
request_str = "GET /index.html?query=test HTTP/1.1\r\nAccept-Encoding: ...\r\n ..." # abbreviated
req = HTTPRequest.read( request_str ) # type: HTTPRequest
req.path_params['query'] = "<script>alert(1)</script>" (this is a bad example, since you should probably urlencode this)
new_request_str = req.write()

public facing api is as follows:
@staticmethod
read( request : string )
	create new HTTPRequest object from string

@staticmethod
read_from_zap_message( zapmsg : dict )
	create new HTTPRequest object from a value returned by zap.core.messages() (for example)

write( httprequest : HTTPRequest )
	return the message as an HTTP-compliant string to sent to a website

write_url( )
	return just the url as a string. The url is composed of the path and path params

copy()
	copy the HTTPRequest object. Usefull for having 1 'ground truth' message and testing several alterations

Additionally, there are several fields which are expected to be directly modified to change the contents of the Request

verb : http verb (GET, POST, etc. Does not have to be a real verb, but should be uppercase letters only )
path : request path ( /index.html, localhost/setup.php, etc. No url parameters )
path_params: dictionary of url parameters ( {'query':'searched', 'lang':'en', 'no_value':None } )
http_version: http version string, usually "HTTP/1.1"
body : body of the request. No special encoding, just a string

'''
class HTTPRequest:
	def __init__(
		self,
		verb="GET",
		path="/",
		path_params={},
		http_version="HTTP/1.1",
		headers={},
		body="",
	):
		#TODO validation
		self.verb = verb
		self.path = path
		self.path_params = path_params
		self.http_version = http_version
		self.headers = headers
		self.body = body
	
	def copy( self ):
		return deepcopy( self )
	

	# parses HTTP request string into HTTPRequest object
	# if it get's anything other than a well-formed HTTP string, it'll probably break
	@staticmethod
	def read( request_str ):
		header,body = spliton( request_str, "\r\n\r\n")
		headerlines = header.split("\r\n")
		assert( len( headerlines ) >= 1 )
		verb,path,path_params,http_version = read_first_line( headerlines[0] )
		hdrs = read_headers( headerlines[1:] )
		return HTTPRequest(verb=verb,path=path,path_params=path_params,http_version=http_version,body=body,headers=hdrs )
	
	@staticmethod
	def read_from_zap_message( zapmsg ):
		assert( 'requestHeader' in zapmsg and 'requestBody' in zapmsg )
		return HTTPRequest.read( zapmsg['requestHeader'] + zapmsg['requestBody'] )


	@staticmethod
	def write( req ):
		return req.write()
	
	def __str__(self):
		return self.write()
	

	
	def write_url( self ):
		return write_url( self.path, self.path_params )
	


	# returns the string representation of the http header
	# write( read( str ) ) == str for any str
	# read( write( hdr ) ) == hdr for any hdr
	def write( self ):
		assert( self.verb is not None )
		assert( self.path is not None )
		assert( self.path_params is not None )
		assert( self.http_version is not None )
		assert( self.headers is not None )
		assert( self.body is not None )
		first_line = "{} {} {}".format( 
			self.verb,
			self.write_url(),
			self.http_version)
		hdrs = write_headers( self.headers )
		return "{}\r\n{}\r\n{}".format( first_line, hdrs, self.body )


# some pure helper methods

# given a string like "GET /index.html HTTP/1.1" returns (verb,path,path_params,http_version)
# pretty fragile, if there are not 3 words in the input string, we'll fail
def read_first_line( line_str ):
	verb,url,http_version = line_str.split( )
	path,params_str = spliton(url, "?" )
	if( not params_str ):
		path_params = {}
	else:
		path_params = read_path_params( params_str  )

	return (verb,path,path_params,http_version)

# take list/iterator of strings like ["connection: close", "Host: google.com" ]
# returns dict of headers in the form {"connection": "close", ... }
def read_headers( hdrs ):
	return { k:v for (k,v) in
		(map(
			(lambda s: spliton( s, ": ")),
			hdrs )) }

#partition the string into two parts
# before substring, after substring
# the substring is discarded
# if the substring is not found, it will return (string, None)
# spliton( "abcde", "cd" ) returns ("ab", "e")
# spliton( "abcde", "f" ) returns ("abcde", "" )
def spliton( string, substr ):
	idx = string.find( substr )
	if( idx < 0 ):
		return (string, None )
	else:
		return (string[:idx], string[idx+len(substr):] )

# give this everything after the '?' in the url
def read_path_params( params_str ):
	return { k:v for (k,v) in
		(map (
			(lambda s: spliton( s, "=" )),
			(params_str.split( "&")) )) }

def write_url( path, path_params ):
	if( not path_params ):
		return path
	else:
		return path + "?" + urllib.parse.urlencode( path_params )

# take a dict like {"connection":"close", "host":"localhost" } and
# output a string like
# "connection: close\r\nhost: localhost\r\n"
# that would appear an HTTP request
# note the trailing \r\n
def write_headers( hdrs ):
	return "".join( ("{}: {}\r\n".format(k,v) for (k,v) in hdrs.items() ) )
