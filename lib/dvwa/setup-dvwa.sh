#!/bin/bash

IMAGENAME='infoslack/dvwa'

echo -n "Checking if docker is installed: "
dpkg -l docker docker.io &> /dev/null
if [[ $? -ne 0 ]]
then
	echo "FAILED"
	echo "Try running ./install.sh"
	echo "Or run 'apt-get install docker docker.io"
	exit -1
else
	echo "PASSED"
fi

echo -n "Checking if dockerd is running: "
if [[ ! -f /var/run/docker.pid ]]
then
	echo "FAILED"
	echo "Please start the docker daemon"
	exit -1
else
	echo "PASSED"
fi


echo -n "Checking if user ${USER} has docker permissions: "
groups $USER | grep 'docker' &> /dev/null
if [[ $? -ne 0 ]]
then
	echo "FAILED"
	echo "Make sure user ${USER} is a member of the docker group"
	exit -1
else
	echo "PASSED"
fi


echo -n "Checking for presence of dvwa image: "
docker images | grep ${IMAGENAME} &> /dev/null
if [[ $? -ne 0 ]]
then
	echo "NOT FOUND"
	echo -n "Pulling from docker registry: "
	docker pull infoslack/dvwa &> /dev/null
	echo "DONE"
else
	echo "PASSED"
fi

echo -n "Starting dvwa container: "
if ! [[ $(docker ps | grep ${IMAGENAME} ) ]]
then
	docker run -d -p 80:80 infoslack/dvwa &> /dev/null
fi
echo "DONE"

# wait for the website to be up
sleep 1s

echo -n "Setting up database: "
OUTPUT=$(python3 ./setup_dvwa.py)
if [[ $? -ne 0 ]]
then
	echo "FAILED"
	echo "You may need to do this manually, or re-run the python script"
else
	echo "DONE"
	echo ${OUTPUT}
fi

