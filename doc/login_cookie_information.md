To create a custom login script, you need to have information regarding some 
of the session cookies, csrf tokens and other specific variables. There are 
multiple ways of finding this information. This contians a few descriptions of 
how to find that information. 

Firefox:
	1. Go to login page of the service you want to test
	2. Press the F12 key to open the Firefox command console. 
	3. Login to the service.
	4. Under the 'Network' section of the prompt you should see a list of requests. Click on a 302 POST request that is made for the login page. (whatever the login page may be called) 
	5. At the bottom should appear various header data for that POST request, click on 'Edit and Resend'
	6. You should now see two sections labeled as 'Request Headers' and 'Request Body'. 
	7. All the cookie information should be located in the cookie line in Request Headers. 
	8. All the data (usernames/passwords/csrfs) should be in the Request body. 
	9. Use the variable names along with information from the url page source to create a login script. 

Chrome:
	1. Go to login page of the service you want to test.
	2. Press the F12 key to open the Chrome command console. 
	3. Login to the service. 
	4. Under the 'Network' section of the prompt you should see a list of requests. Click on a 302 POST request that is made for the login page. (whatever the login page may be called)
	5. Click on the 'Cookies' subtab for that request, and you will see information for all of the various cookies that are returned. 
	6. Click on the 'Headers' subtab for that request, and you will see information ffor all the headers of that POST request. 
	7. In the 'Form Data' in that 'Headers' subtab, you can see the variables filled and sent to the login page. 

Opera:
	1. Go to login page of the service you want to test. 
	2. Press Ctrl+Shift+I to open Developer Tools.
	3. Login to the service. 
	4. Under the 'Network' section of the prompt you should see a list of requests. Click on a 302 POST request that is made for the login page. (whatever the login page may be called)
	5. Click on the 'Cookies' subtab for that request, and you will see information for all the various cookies that are returned. 
	6. Click on the 'Headers' subtab for that request, and you will see information for all the headers of that POST request. 
	7. In the 'Form Data' in that 'Headers' subtab, you can see the variables filled and sent to the login page. 

Burp (community edition):
	1. Setup Burp if not done so already 
	2. Make sure that intercept is on and make a request to the login site of the service 
	3. Login into the service and you can see the cookie and data information in the raw tab
