# Gray box authentication

Currently ADAPT is setup only for a particular type of authentication, namely to push the login responsibility to the user. The reason for doing this is that websites are too disparate to make an effective generic login script. 

In order to get graybox testing for ADAPT, the user must provide a python script that gives back the relevant header and cookie information that ADAPT uses. 

See the file: login_format.py for specific details regarding expected inputs/outputs/function calls.


