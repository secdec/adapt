from bs4 import BeautifulSoup
import requests
import time

def get_setup_page( client, host='localhost:80' ):
	url = host+"/setup.php"
	while( True ):
		try:
			time.sleep( 1 )
			page = client.get( url )
			return page
		except Exception as e:
			continue
	return page

def get_form_params( raw_page ):
	soup = BeautifulSoup( raw_page.text, "html.parser" )
	form = soup.find( "form" )
	inputs = form.findAll("input")
	ret = {}
	for i in inputs:
		if( i.has_attr('value') ):
			ret[i['name']] = i['value']
		else:
			ret[i['name']] = None
	return ret

def setup_db(client, host):
	page = get_setup_page(client, host=host)
	params = get_form_params( page )
	newpage = client.post( page.url, data=params )


host = "localhost:80"
if(not ( host.startswith("http://") or host.startswith("https://") ) ):
	host = "http://"+ host
client = requests.session()
setup_db( client, host )
