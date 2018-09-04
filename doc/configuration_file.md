The configuration file: adapt.config
Recommended values are values that are configurable, but not encouraged to be unchanges unless for specific circumstances. 

Confidence/risk values:
	paranoid : All results will be valid no matter how seemingly unimportant. 
	low : Only low and higher confidences/risks will be reported. 
	medium : Only medium and higher confidences/risks will be reported. 
	high : Only high confidences/risks will be reported. 

Sections:

	GENERAL_OPTIONS
		General options regarding ADAPT runtime and handling

	OUTPUT_OPTIONS
		Options about ADAPT's output formatting 

	SSH_OPTIONS
		Options about collecting server log information via ssh

	OWASP_ZAP_OPTIONS
		Options that are tooled to zap specifically

	AUTH_OPTIONS
		Options webservice authentication 

	OWASP_OPTIONS
		Options regarding the general owasp test suite thats implemented

	DEBUG_OPTIONS
		Various debug options

ADAPT:
	target : The webservice target. If attacking a specific port, it must be specified in the target name e.g. 'http://localhost:8000'
			 Please take care to note distinctions between https and http in your target name. They are treated differently and 
			 conflating the two as equivalent is unsupported. 

	context : The overall webpage name. This is to give a hard limit to what will be searched. 
	
	confidence : Determines how sensitive ADAPT should be in decerning results. (recommended: paranoid) 

	risk : Determines how sensitive ADAPT is to discovered risks. (recommended: paranoid) 

	detail : How much detail should be expressed when done? (recommended: full)
		low : almost pass/fail 
		medium : more specific errors are reported. 
		high : more collected information (like paths) are reported. 
		full : all collected information is returned. 

	nmap_script_ports : Which ports should the nmap script target?
		all : sets to look at all ports 
		default : sets to 80
		skip : will not run nmap 
		[space separated list of integers] : runs against those ports 

OUTPUT:
	filetype : output will be either json or xml (recommended: json)
	specific_filename : This will save output to this file. This will supercede filetype. 
	append : similar to specific filename but it appends to data file instead of overwrite. 

SSH:
	ssh_get_logs : This turns ssh log capture on/off
	
	hostname : the hostname to connect to 

	username : the username to use. Use //stdin to enter user via stdin. 
	password : the password to use. Use //stdin to enter password via stdin. 

	keywords : Capture lines with these space separated keywords. If set to 'none', will default to [ERROR, error, WARNING, warning]

	log_paths : The space separated list of complete file paths to the log files. 

	read_amount : Limit the number of lines looked at. 

	read_direction : Choose a direction to read from. 
		full : read entire file (Supercedes read_amount)
		top : start reading from the top of the file 
		bottom : start reading from the bottom of the file 

ZAP:
	passive_scan : Turns passive scanning on/off (recommended: on)

	spider_scan : Turns spidering on/off (recommended: on)

	active_scan : Turns active scanning on/off (recommended: on)

	api_key : The specified api_key for zap. Default is none. (recommended: none)

	exclude : Space separated list of all paths that are to be excluded from testing/directory traversal/injection. 

AUTH:
	auth_module : the name of the custom python login script goes here. 

	valid_username : A valid username to login to the service. Use //stdin to enter via stdin. 

	valid_password : A valid password to login to the service. Use //stdin to enter via stdin

OWASP:
	Only on/off options for each OWASP test. 

DEBUG:
	ADAPT_verbose : Turns terminal verbose on/off (recommended: on)

	zap_close : Closes zap after done testing on/off (recommended: on)

	zap_hidden : Zap gui on/off. (recommended: on) If turned on, zap will automatically close despite zap_close.
