#!/usr/bin/env ruby

# Class ListQueuerConfiguration is a simple object representation of the xml configuration file
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'rexml/document'
require 'uri'

class ListQueuerConfiguration
	attr_accessor :uris


	#initializer that will parse the configuration file that was passed in
	#and makes it available via the instance variables
	def initialize(configuration_file_location)
		@uris = Array.new
			
		file = File.new( configuration_file_location )
		doc = REXML::Document.new file
		
		doc.elements.each("listQueuerConfiguration/uri") { |uri|
			@uris.push(URI.unescape(uri.text))
		}
	end

end

#!/usr/bin/env ruby

# Class ListQueuerConfigurationTest is a simple unit test of ListQueuerConfiguration
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'

class ListQueuerConfigurationTest < Test::Unit::TestCase

	def test_read_configuration
		conf = ListQueuerConfiguration.new("queuer/ListQueuerConfigurationUnitTest.xml")

		uris = Array.new
		uris.push("http://www.unit.com")
		uris.push("http://www.unittest.com/index.html?sometest=one&otherparam=one and two")
		uris.push("http://www.unittest.com/index.html?sometest=one&otherparam=three and two")
		assert_equal(uris,conf.uris,"uris not as expected.")
	end
end

#comment the next two lines out to enable running this unit test by executing
# ruby queuer/ListQueuerConfiguration.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(ListQueuerConfigurationTest)