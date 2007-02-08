#!/usr/bin/env ruby

# Class SnortRulesAnalysisEngineConfiguration is a simple object representation of the xml configuration file
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'rexml/document'

class SnortRulesAnalysisEngineConfiguration
	attr_accessor :rules_location


	#initializer that will parse the configuration file that was passed in
	#and makes it available via the instance variables
	def initialize(configuration_file_location)
		@rules_location = ""
		
		file = File.new( configuration_file_location )
		doc = REXML::Document.new file
		
		@rules_location = doc.elements["snortRulesAnalysisEngineConfiguration/rulesLocation"].text 
	end

end

#!/usr/bin/env ruby

# Class SnortRulesAnalysisEngineConfigurationTest is a simple unit test of SnortRulesAnalysisEngineConfiguration
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'

class SnortRulesAnalysisEngineConfigurationTest < Test::Unit::TestCase
	#test that passes location of a configuration file and checks whether 
	#the generates instance variable match
	def test_read_configuration
		conf = SnortRulesAnalysisEngineConfiguration.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest.xml")
		assert_equal("analysisEngine/unittest.rules",conf.rules_location,"rules location not as expected.")

	end
end

#comment the next two lines out to enable running this unit test by executing
# ruby analysisEngine/SnortRulesAnalysisEngineConfiguration.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRulesAnalysisEngineConfigurationTest)