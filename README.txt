Introduction
------------
HoneyC is a low interaction client honeypot that allows to identify malicious servers on the web. Instead of using a fully functional operating system and client to perform this task (which is done by high interaction client honeypots, such as Honeymonkey or Honeyclient), HoneyC uses emulated clients that are able to solicit as much of a response from a server that is necessary for analysis of malicious content. HoneyC is expandable in a variety of ways: it can use different visitor clients, search schemes, and analysis algorithms. For more information on the internals of HoneyC refer to section HoneyC Internals.


Installation
------------
If you are using component modules (visitor, queuer, and analysisEngine) that are provided as part of the HoneyC distribution, installation of HoneyC is trivial as it is written in Ruby, a platform independent interpreter language.
Simply install your favorite ruby development environment (execute ‘ruby -v’ on the command line to check whether a ruby environment already exists) Unpack the HoneyC distribution into a directory, cd into that directory, and execute ‘ruby UnitTester.rb’. This will start the unit tests executing some basic module tests. (Note that you need to have network connectivity and direct outgoing access on port 80 for the unit tests to succeed.)

To invoke HoneyC with the default configuration options that were set with the distribution execute ‘ruby -s HoneyC.rb -c=HoneyCConfigurationExample.xml’. For this particular version 1.x.x, the default configuration options were making use of the http modules queuer/YahooSearch, visitor/WebBrowser, and analysisEngine/SnortRulesAnalysisEngine. (please refer to the corresponding documentation of these modules for additional information on how to configure them by invoking ruby module --help, for example ‘ruby queuer/YahooSearch.rb --help’) This combination of modules interacts with the Yahoo Search API to obtain several URIs to be visited by a simple web browser implementation based on provided search query strings. The responses received are being analyzed against simple snort rules (regex, content and uri matching). For each match, a snort alert is raised. Note: The current snort rules do not perform an analysis for malware. Rather, they are currently containing some simple regex examples that demonstrate that the analysisEngine could perform this search in case the search criteria are known. Meaningful malware snort rules will be added in future releases of honeyC.


Release Notes
-------------
1.x.x - implemented flow_bit evaluation (feature 1629168)
        performance optimizations
	added functionality to snort rules permutator (additional encoding schemes, ability to replace substrings in regex and dealing with nocase content fields)
1.2.0 - fixed bug 1621117 
	fixed bug 1622156
	fixed bug 1623277
	fixed bug 1623973
	fixed bug 1623978
	fixed bug 1622174
	fixed bug 1622200 
	fixed bug 1623202 
	fixed bug 1623301 
	fixed bug 1623304
	added new headercontent tag and H option to PCRE to support matching on http header content only. (feature request 1623977)
	added a little tool that allows to permutate snort rules (UUencoding currently is the only permutation supported)
1.1.6 - fixed bug 1621073
	fixed bug 1621072
1.1.5 - added simple history to web browser that acts as a cache (feature request 1538329)
	implemented a check for snort rules at parsing time (feature request 1584976)
	implemented stats module for analysis engine (feature request 1588345)
	fixed bug 1585553 
	fixed bug 1585946
	fixed bug 1586219 
1.1.4 - fixed bug 1580976 
	fixed bug 1581017 
	fixed bug 1581507 - too a certain extend. if rules dont adhere to the official format, HoneyC is not going out of its way to deal with the nuiances of these diviations.
	fixed bug 1581010 
	fixed bug 1581015 
	added http response parameters (feature request 1568930)
1.1.3 - fixed bug 1566579
	refactored snort rules analysis engine to use a lexer, parser. functionality is more feature rich.
	extended yahoo search api queuer to allow specification of format tags effectively allowing to filter for pdf, ppt, etc. (feature request 1572360)
	adjusted web browser configuration so one can specify the number of concurrent threads. a default value of 20 is set, but it is recommended to do some tests to find the optimum value for your environment. (feature request 1572361)
	adjusted web browser, so it can be configured to follow a links that are included in the response (feature request 1571863)
	taking into account host name lookups for performance enhancement of web browser (feature request 1568932)
1.1.2 - added redirect following support to the web browser (feature request 1567472)
	extend yahoo search api queuer to allow 1000 results (feature request 1568064)
	fixed bug 1568003 around empty request path
	add queuer to simply take a list of urls (feature request 1563204)
	threaded fetching of web content in web browser and added timeout of 10 sec per request (feature request 1568140)	
1.1.1 - added queuer support for proxy (feature request 1550276)
1.1.0 - added support for proxy (feature request 1535522)
      	added additional functionality to snort rules analysis engine. it now is able to utilize a big portion of the bleeding edge snort malware rules (feature request 1535521)
	added automated test cases for functional tests. they are contained in the unit test suite and the test method name ends with tc<id>, e.g. tc17 for test case 17.
1.0.5 - fixed bug 1540308, which caused honeyC to fail on urls with xml special characters (e.g. <)
	adjusted rules and queuer list to be more meaningful examples
1.0.4 - "fixed" unit tests.
	adjusted error handling in WebBrowser and AnalysisEngine
1.0.3 - fixed bug 1538335, which caused honeyC to fail in case of a timeout.
1.0.2 - fixed bug 1537298, which caused honeyC to fail on malformed url
	fixed bug 1537162, which prevented the yahoo search query from exceeding if results where larger than the yahoo search api limit of 100.
1.0.1 - fixed typos in the README file
	fixed bug 1535708, which prevented honeyC from running on linux.
	fixed bug 1536314, which caused honeyC to fail on a bad response.
1.0.0 - initial version of HoneyC. The framework comes with three modules (queuer/YahooSearch, visitor/WebBrowser, and analysisEngine/SnortRulesAnalysisEngine) that allow to instantiate HoneyC to act as a browser based client honeypot. Simple http request and http response are the request and response that are currently supported by HoneyC.
