# class that allows to output snort fast alerts upon rule matches
# the format matches the snort fast alert format with the exception of the ip address
# being converted to localhost and the uri
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require "response/HttpResponse"
require "analysisEngine/SnortRule"
require "analysisEngine/SnortRuleFlowBit"


class SnortFastAlerter
	#outputs the alert
	def SnortFastAlerter.output_rule_match(rule_match, http_response)
		if(!SnortFastAlerter.suppress_alert?(rule_match))
			alert = Time.now.strftime("%m/%d-%H:%M:%S.000000") + " [**] "\
				+ "[1:" + rule_match.sid.to_s + ":" + rule_match.rev.to_s + "] " + rule_match.msg\
				+ " [**] [Classification: " + rule_match.class_type_long + "] [Priority: "\
				+ rule_match.priority.to_s + "] {TCP} localhost -> " + http_response.uri
			return alert
		else
			return ""
		end
	end
	
	#general error
	def SnortFastAlerter.output_general_error(error_string, uri)
		alert = Time.now.strftime("%m/%d-%H:%M:%S.000000") + " [**] "\
	 		+ "[1:2000000:1] " + error_string\
			+ " [**] [Classification: Unknown Traffic] [Priority: 3] "\
			+ "{TCP} localhost -> " + uri
		return alert
	end
	
	def SnortFastAlerter.suppress_alert?(rule)
		suppress_alert = false
		rule.flow_bits.each { |flow_bit|
			return true if(flow_bit.key_word.eql?("noalert"))
		}
		return suppress_alert 
	end
end


#!/usr/bin/env ruby

# Class SnortFastAlerterTest is a simple unit test of SnortFastAlerter
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'

class SnortFastAlerterTest < Test::Unit::TestCase
	#test output_rule_match
	def test_output_rule_match
		references = Array["reference1","reference2"]
		
		snort_rule = SnortRule.new
		snort_rule.msg="msg"
		snort_rule.references = references
		snort_rule.rev = 1
		snort_rule.sid = 2000000
		snort_rule.class_type = "trojan-activity"
		snort_rule.priority = 1
		
		http_response = HttpResponse.new("http://www.test.com",200,"<body>test url</body>",Hash.new)
		snort_fast_alert = SnortFastAlerter.output_rule_match(snort_rule,http_response)
		
		match_date = /[0-9][0-9]\/[0-9][0-9]-[0-9][0-9]:[0-9][0-9]:[0-9][0-9].000000/ =~ snort_fast_alert.to_s
		assert(match_date,"to_s date not as expected:" + snort_fast_alert.to_s)
		
		remaining_string = " [**] [1:2000000:1] msg [**] [Classification: A Network Trojan "\
			+ "was detected] [Priority: 1] {TCP} localhost -> http://www.test.com"
		assert_equal(remaining_string, snort_fast_alert.to_s[21..snort_fast_alert.to_s.length],\
			"to_s rest not as expected:" + snort_fast_alert.to_s)

	end
	
	def test_suppress_alert
		snort_rule = SnortRule.new
		flow_bit = SnortRuleFlowBit.new
		flow_bit.key_word = "noalert"
		snort_rule.flow_bits.push(flow_bit)
		
		assert(SnortFastAlerter.suppress_alert?(snort_rule),"noalert flow bit doesnt cause supression of alert")
	end
	
	def test_output_general_error
		
		snort_fast_alert = SnortFastAlerter.output_general_error("This is my error at.", "http://www.myerror.com/?whathappend")
		
		match_date = /[0-9][0-9]\/[0-9][0-9]-[0-9][0-9]:[0-9][0-9]:[0-9][0-9].000000/ =~ snort_fast_alert.to_s
		assert(match_date,"date not as expected:" + snort_fast_alert.to_s)
		
		remaining_string = " [**] [1:2000000:1] This is my error at. [**] [Classification: Unknown Traffic] "\
			+ "[Priority: 3] {TCP} localhost -> http://www.myerror.com/?whathappend"
		assert_equal(remaining_string, snort_fast_alert.to_s[21..snort_fast_alert.to_s.length],\
			"rest not as expected:" + snort_fast_alert.to_s)

	end
end

#comment the next two lines out to enable running this unit test by executing
# ruby analysisEngine/SnortFastAlerter.rb
#require 'test/unit/ui/console/testrunner'
#Test::Unit::UI::Console::TestRunner.run(SnortFastAlerterTest)