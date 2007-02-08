#!/usr/bin/env ruby

# Class HoneyCConfiguration is a simple object representation of the xml configuration file
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'rexml/document'

class HoneyCConfiguration
	attr_accessor :visitor, :queuer, :analysis_engine


	#initializer that will parse the configuration file that was passed in
	#and makes it available via the instance variables
	def initialize(configuration_file_location)		
		file = File.new( configuration_file_location )
		doc = REXML::Document.new file
		
		@visitor = doc.elements["honeyCConfiguration/visitor"].text
		@queuer = doc.elements["honeyCConfiguration/queuer"].text
		@analysis_engine = doc.elements["honeyCConfiguration/analysisEngine"].text
	end

end

#!/usr/bin/env ruby

# Class HoneyCConfigurationTest is a simple unit test of HoneyCConfiguration
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'

class HoneyCConfigurationTest < Test::Unit::TestCase
	#test that passes location of a configuration file and checks whether 
	#the generates instance variable match
	def test_read_configuration
		conf = HoneyCConfiguration.new("HoneyCConfigurationUnitTest.xml")
		assert_equal("ruby -s visitor/WebBrowser.rb -c=visitor/WebBrowserConfigurationUnitTest.xml",conf.visitor,"visitor not as expected.")
		assert_equal("ruby -s queuer/YahooSearch.rb -c=queuer/YahooSearchConfigurationUnitTest2.xml",conf.queuer,"queuer not as expected.")
		assert_equal("ruby -s analysisEngine/SnortRulesAnalysisEngine.rb -c=analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest.xml"\
			,conf.analysis_engine,"analysis engine not as expected.")
		
	end
end

#comment the next two lines out to enable running this unit test by executing
#ruby HoneyCConfiguration.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(HoneyCConfigurationTest)