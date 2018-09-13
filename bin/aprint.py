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

from pprint import pprint

class aprint():
	def __init__(self, verbose, home_file="adapt", gui=None):
		self.verbose = verbose
		self.home_file = home_file
		self.crits = {0:" [INFO] : ", 1:" [WARN] : ", 2:" [CRIT] : "}
		self.gui = None

	def set_gui(self, g):
		self.gui = g

	def __gc(self, c):
		return self.crits.get(c, " INFO] ")

	def rprint(self, msg, c=0):
		return self.home_file+self.__gc(c)+msg

	def aprint(self, msg, c=0):
		if(not self.verbose):
			return
		if(self.gui != None):
			try:
				self.gui(self.home_file+self.__gc(c)+msg)
			except:
				self.gui = None
				self.aprint("GUI WINDOW ERROR", c=2)
				self.aprint(msg, c=c)
		else:
			pprint(self.home_file+self.__gc(0)+msg)
