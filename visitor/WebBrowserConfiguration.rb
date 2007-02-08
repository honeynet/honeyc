#!/usr/bin/env ruby

# Class WebBrowserConfiguration is a simple object representation of the xml configuration file
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'rexml/document'

class WebBrowserConfiguration
	attr_accessor :user_agent, :server, :port, :username, :password, :browser_threads, :follow_a_link, :url_filter

	#initializer that will parse the configuration file that was passed in
	#and makes it available via the instance variables
	def initialize(configuration_file_location)
		@user_agent = ""
		@browser_threads = 20
		
		file = File.new( configuration_file_location )
		doc = REXML::Document.new file
		
		@user_agent = doc.elements["webBrowserConfiguration/userAgent"].text 
		@browser_threads = doc.elements["webBrowserConfiguration/browserThreads"].text.to_i if doc.elements["webBrowserConfiguration/browserThreads"] != nil
				
		@server = doc.elements["webBrowserConfiguration/proxy/server/"].text if doc.elements["webBrowserConfiguration/proxy/server/"] != nil
		@port = doc.elements["webBrowserConfiguration/proxy/port/"].text.to_i if doc.elements["webBrowserConfiguration/proxy/port/"] != nil
		@username = doc.elements["webBrowserConfiguration/proxy/username/"].text if doc.elements["webBrowserConfiguration/proxy/username/"] != nil
		@password = doc.elements["webBrowserConfiguration/proxy/password/"].text if doc.elements["webBrowserConfiguration/proxy/password/"] !=nil

		@url_filter = doc.elements["webBrowserConfiguration/urlFilter"].text if doc.elements["webBrowserConfiguration/urlFilter"] !=nil
	end

end

#!/usr/bin/env ruby

# Class WebBrowserConfigurationTest is a simple unit test of WebBrowserConfiguration
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'

class WebBrowserConfigurationTest < Test::Unit::TestCase
	#test that passes location of a configuration file and checks whether 
	#the generates instance variable match
	def test_read_configuration
		conf = WebBrowserConfiguration.new("visitor/WebBrowserConfigurationUnitTest.xml")
		assert_equal(1,conf.browser_threads,"browser threads not as expected.")
		assert_equal("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",conf.user_agent,"user agent not as expected.")
		assert_equal("gif|jpg",conf.url_filter,"url filter not as expected.")

	end
	
	#test that passes location of a configuration file and checks whether 
	#the generates instance variable match
	def test_read_configuration_proxy
		conf = WebBrowserConfiguration.new("visitor/WebBrowserConfigurationUnitTestProxy.xml")
		assert_equal(20,conf.browser_threads,"browser threads not as expected.") #default value
		assert_equal("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",conf.user_agent,"user agent not as expected.")
		assert_equal("192.168.74.3",conf.server,"proxy server not as expected")
		assert_equal(3128,conf.port,"proxy server port not as expected")
		

	end
	
	#test that passes location of a configuration file and checks whether 
	#the generates instance variable match
	def test_read_configuration_proxy_auth
		conf = WebBrowserConfiguration.new("visitor/WebBrowserConfigurationUnitTestProxyAuth.xml")
		assert_equal(20,conf.browser_threads,"browser threads not as expected.") #default value
		assert_equal("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",conf.user_agent,"user agent not as expected.")
		assert_equal("192.168.74.3",conf.server,"proxy server not as expected")
		assert_equal(3128,conf.port,"proxy server port not as expected")
		assert_equal("username",conf.username,"proxy username not as expected")		
		assert_equal("password",conf.password,"proxy password not as expected")
	end
end

#comment the next two lines out to enable running this unit test by executing
# ruby visitor/WebBrowserConfiguration.rb
#require 'test/unit/ui/console/testrunner'
#Test::Unit::UI::Console::TestRunner.run(WebBrowserConfigurationTest)