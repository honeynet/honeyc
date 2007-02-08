#!/usr/bin/env ruby

# object representation of a snort rule headercontent - note that this is a custom element not compatible to snort ids rules.
# since, the httpresponse representation is in the format <header name="key">value</header> one can specify
# to match on a specific header by including name="key"> as part of the expression.
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'analysisEngine/SnortRuleContent'

class SnortRuleHeaderContent < SnortRuleContent
	
	def to_s
		not_mod = "!" if not_modifier
		"HeaderContent["+ @order_number.to_s + "]:[" + not_mod.to_s + " " + unescaped_string.to_s + ", within:" + within.to_s\
		 + ", distance:" + distance.to_s + ", offset:" + offset.to_s + ", depth:" + depth.to_s\
		 + ", " + raw_bytes.to_s + ", " + nocase.to_s + "] "
		
	end
	
	def to_r
		not_mod = "!" if not_modifier
		header_content_str = "headercontent:" + not_mod.to_s + "\"" + unescaped_string.to_s + "\"; "
		header_content_str = header_content_str + "nocase; " if nocase
		header_content_str = header_content_str + "rawbytes; " if raw_bytes
		header_content_str = header_content_str + "depth:"+depth.to_s+"; " if depth
		header_content_str = header_content_str + "within:"+within.to_s+"; " if within
		header_content_str = header_content_str + "distance:"+distance.to_s+"; " if distance
		header_content_str = header_content_str + "offset:"+offset.to_s+"; " if offset
		header_content_str
	end
	
	def eql?(object)
		return self.to_s == object.to_s
	end
	
	def ==(object)
		return self.to_s == object.to_s
	end
end

require 'test/unit/testcase'

class SnortRuleHeaderContentTest < Test::Unit::TestCase


	#test simple case sensitive match with binary data
	def test_match_case_sensitive_binary
		#uri_content with exact match
		header_content = "first line.\nthis string contains a case sensitive match on: MyMatch123"
		snort_rule_header_content = SnortRuleHeaderContent.new
		snort_rule_header_content.unescaped_string = "M|79|Mat|63 68|123" #equals MyMatch123
		snort_rule_header_content.nocase = false
		
		match = snort_rule_header_content.match(header_content,0)
		assert_equal(60, match,"no case sensitive match on header content.")
	end
	
	def test_to_r
		snort_rule_header_content = SnortRuleHeaderContent.new
		snort_rule_header_content.not_modifier = false
		snort_rule_header_content.unescaped_string = "mymatch123"
		snort_rule_header_content.nocase = true	
		
		expected_str = "headercontent:\"mymatch123\"; nocase; "
		assert_equal(expected_str,snort_rule_header_content.to_r,"To R not correct.")
	end
end

#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRuleHeaderContentTest)
