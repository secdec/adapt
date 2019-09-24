#!/bin/bash

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

if [[ $EUID -eq 0 ]]; then
echo "This script should no longer be run as root"
exit 1
fi

launch_dir=$(pwd)

function do_command {
	echo -n "$@: "
	$@ &>/dev/null
	if [[ ! $? ]]
	then
		echo "FAILED"
		exit -1
	else
		echo "DONE"
	fi
}

if [ "$1" == "clean" ]; then
	echo "Cleaning..."
	cd "$launch_dir"/output
	rm *
	cd "$launch_dir"
	cd "$launch_dir"/static_data
	rm -rf SecLists
	cd "$launch_dir"
	cd "$launch_dir"/tools
	rm -rf "$launch_dir"/lib/paramiko
	rm -rf "$launch_dir"/lib/testssl.sh
	cd "$launch_dir"
	
	exit 0
fi

if [ "$(uname)" == "Darwin" ]; then
echo "Installing for MacOSX"
	pip3 install python-owasp-zap-v2.4
	pip3 install beautifulsoup4
	pip3 install lxml
	pip3 install dicttoxml
	pip3 install scipy
	pip3 install paramiko
	python3 setup.py install
elif [ "$(uname -s)" == "Linux" ]; then
	sudo --validate # update sudo permissions, so we don't have to enter a passwd for the rest of the script
	echo "Installing for Linux: "
	echo "Please do not press anything until the script is finished, go take a break"
	do_command sudo apt-get update -y
	do_command sudo apt-get install python3-pip -y
	do_command sudo apt-get install python3-scipy -y
	do_command sudo apt-get install default-jre -y
	do_command sudo apt-get install nmap -y
	do_command sudo apt-get install docker.io -y
	do_command sudo apt-get install git -y
	do_command sudo apt-get install python-pip python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev
	echo -n "Checking for zap: "
	if [ ! -d /opt/ZAP_2.7.0 ]
	then
		echo "NOT FOUND"
		echo -n "Installing zap: "
		sudo apt-get install wget -y &> /dev/null
		sudo wget -q -O /opt/zap.tar.gz https://github.com/zaproxy/zaproxy/releases/download/2.7.0/ZAP_2.7.0_Linux.tar.gz &> /dev/null
		sudo tar -xf /opt/zap.tar.gz -C /opt
		if [[ -d /opt/ZAP_2.7.0 ]]
		then
			sudo rm /opt/zap.tar.gz
			echo "DONE"
		else
			echo "FAILED"
			exit 1
		fi
	else
		echo "FOUND"
	fi
	
	# checking for wig
	echo -n "Checking for wig: "
	python3 -c "import wig.wig" &> /dev/null
	if [ $? -ne 0 ]
	then
		echo "NOT FOUND"
		echo -n "Installing wig: "
		sudo git clone https://github.com/jekyc/wig &> /dev/null
		cd wig
		ERROR=$(sudo python3 setup.py install)
		if [ $? -ne 0 ]
		then
			echo "FAILED"
			echo ${ERROR}
		fi
			echo "DONE"
			sudo rm -rf wig*
		else
			echo "FOUND"
		fi
		cd -

	echo -n "Checking paramiko: "
	cd "$launch_dir"/lib
	if [ ! -d ./paramiko ]
	then
		echo "NOT FOUND"
		echo -n "Installing paramiko dev: "
		sudo git clone https://github.com/paramiko/paramiko &> /dev/null
		cd "$launch_dir"/lib/paramiko
		ERROR=$(sudo python3 setup.py install)
		if [ $? -ne 0 ]
		then
			echo "FAILED"
			echo ${ERROR}
		fi
			echo "DONE"
	else
		echo "FOUND"
	fi
	cd "$launch_dir"

	echo -n "Checking testssl: "
	cd "$launch_dir"/lib
	if [ ! -d ./testssl.sh ] 
	then
		echo "NOT FOUND"
		echo "Installing testssl dev: "
		sudo git clone https://github.com/drwetter/testssl.sh &> /dev/null
		echo "DONE"
	else
		echo "FOUND"
	fi
	cd "$launch_dir"

	echo -n "Checking for SecLists: "
	cd "$launch_dir"/var
	if [ ! -d ./SecLists ] 
	then
		echo "NOT FOUND"
		echo -n "Installing SecLists: "
		sudo git clone https://github.com/danielmiessler/SecLists.git
		echo "DONE"
	else
		echo "FOUND"
	fi
	cd "$launch_dir"
	

# Make output directory if it does not exist
	if [ ! -d output ]
	then
		sudo mkdir output
	fi

	do_command sudo pip3 install python-nmap
	do_command sudo pip3 install python-owasp-zap-v2.4
	do_command sudo pip3 install paramiko
	do_command sudo pip3 install beautifulsoup4
	do_command sudo pip3 install lxml
	do_command sudo pip3 install dicttoxml
	do_command sudo pip3 install progressbar2
	do_command sudo pip3 install pathlib
	do_command sudo pip3 install bcrypt
	do_command sudo pip3 install pynacl

	# Now to write out a temp file which will indicate that we ran the install script 
	sudo touch ./var/adapt_installed

	echo "ADAPT install: FINISHED"
else
	echo "Unsupported OS, exiting..."
	exit 1
fi
