#!/usr/bin/env ruby

# Class YahooSearchConfiguration is a simple object representation of the xml configuration file
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'rexml/document'

class YahooSearchConfiguration
	attr_accessor :application_id, :queries, :server, :port, :username, :password


	#initializer that will parse the configuration file that was passed in
	#and makes it available via the instance variables
	def initialize(configuration_file_location)
		@queries = Hash.new
		@application_id = ""
		
		file = File.new( configuration_file_location )
		doc = REXML::Document.new file
		
		@application_id = doc.elements["yahooSearchConfiguration"].attributes["applicationID"] 

		@server = doc.elements["yahooSearchConfiguration/proxy/server/"].text if doc.elements["yahooSearchConfiguration/proxy/server/"] != nil
		@port = doc.elements["yahooSearchConfiguration/proxy/port/"].text.to_i if doc.elements["yahooSearchConfiguration/proxy/port/"] != nil
		@username = doc.elements["yahooSearchConfiguration/proxy/username/"].text if doc.elements["yahooSearchConfiguration/proxy/username/"] != nil
		@password = doc.elements["yahooSearchConfiguration/proxy/password/"].text if doc.elements["yahooSearchConfiguration/proxy/password/"] !=nil

		doc.elements.each("yahooSearchConfiguration/query") { |query|
			results = query.attributes["results"].to_i
			if results > 1000 #max results value supported by yahoo search API
				results = 1000
			end
			format = query.attributes["format"]
			format = "all" if format == nil
			@queries[query.text] = results, format
		}
	end

end

#!/usr/bin/env ruby

# Class YahooSearchConfigurationTest is a simple unit test of YahooSearchConfiguration
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'

class YahooSearchConfigurationTest < Test::Unit::TestCase
	#test that passes location of a configuration file and checks whether 
	#the generates instance variable match
	def test_read_configuration
		conf = YahooSearchConfiguration.new("queuer/YahooSearchConfigurationUnitTest.xml")
		assert_equal("_HoneyC_",conf.application_id,"applicationID not as expected.")
		
		queries = Hash.new
		queries["yahoo"]=2, "html"
		queries["google"]=1000, "ppt"
		assert_equal(queries,conf.queries,"queries not as expected.")
	end
	
	#test that passes location of a configuration file and checks whether 
	#the generates instance variable match
	def test_read_configuration_proxy_without_auth
		conf = YahooSearchConfiguration.new("queuer/YahooSearchConfigurationUnitTestProxy.xml")
		assert_equal("_HoneyC_",conf.application_id,"applicationID not as expected.")
		
		queries = Hash.new
		queries["mail.yahoo.com"]=1,"all"
		queries["www.google.com"]=1,"all"
		assert_equal(queries,conf.queries,"queries not as expected.")
		assert_equal("192.168.74.3",conf.server,"proxy server not as expected")
		assert_equal(3128,conf.port,"proxy server port not as expected")
	end
	
	#test that passes location of a configuration file and checks whether 
	#the generates instance variable match
	def test_read_configuration_proxy_with_auth
		conf = YahooSearchConfiguration.new("queuer/YahooSearchConfigurationUnitTestProxyAuth.xml")
		assert_equal("_HoneyC_",conf.application_id,"applicationID not as expected.")
		
		queries = Hash.new
		queries["mail.yahoo.com"]=1,"all"
		queries["www.google.com"]=1,"all"
		assert_equal(queries,conf.queries,"queries not as expected.")
		assert_equal("192.168.74.3",conf.server,"proxy server not as expected")
		assert_equal(3128,conf.port,"proxy server port not as expected")
		assert_equal("username",conf.username,"proxy username not as expected")		
		assert_equal("password",conf.password,"proxy password not as expected")
	end
end

#comment the next two lines out to enable running this unit test by executing
# ruby queuer/YahooSearchConfiguration.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(YahooSearchConfigurationTest)