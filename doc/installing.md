# Installing and running ADAPT

This project has been developed and tested primarily on ubuntu 16.04.
Other OS's may work, but are unsupported

If running in a vm, it is recommended that it is at least dual core and has
4 GiB of memory and 10 GiB of space. 

Depending on the target application, ADAPT can can consume a lot of memory when 
forking processes and storing results. 

There is an install script in the top level directory called install.sh. Run that
The next step is to manually tweak the configuration file. adapt.config

see documentation/configuration_file.md and documentation/authentication.md for info

# DVWA
For testing against a known vulnerable webapp, the dvwa directory may be useful.
In it are scripts to install and run a docker container with the damn vulnerable web app.

Before using dvwa, make sure docker is installed and running, and the user is a member of the 'docker' group.
This is not automated, but the steps will probably look like
$ sudo apt-get install docker
$ sudo gpasswd -a ${USER} docker
Logout, and login again to propogate the group changes
run dvwa/setup-dvwa.sh to start the container and setup the db
manually navigate to localhost to ensure the website is running
the default username/password is "admin"/"password"
if you see 'database not configured' click the setup button manually
target it with ADAPT
