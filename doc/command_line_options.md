# ADAPT command line options


--target <host>: Manually set host as target
--verbose : Turn on verbose mode
--gui : Turn on GUI mode
--output <filename> : Specify an output file to put results into 
--append <filename> : Specify an output file to append results to
--risk <[low, medium, high, paranoid]> : Specify how sensitive the results will be to discovered risks. 
--conf <[low, medium, high, paranoid]> : Specify how sensitive the results will be in regards to confidence levels 
--detail <[low, medium, high, full, owasp10]> : Specify how detailed or included details are put into the final report. 
	low : Functional pass/fail depending on risk/conf values 
	medium : Basic description of an ecountered problem, and how severe it may be. 
	high : Some more information with regards to links/directories/requests and possible tips about prevention 
	full : Even more information with regards to misc information that may have been scraped. 
	owasp10 : An output method that reports only the vulnerabilities in regards to the owasp top 10. (report detail is otherwise full) 
-h, --help : Show help
