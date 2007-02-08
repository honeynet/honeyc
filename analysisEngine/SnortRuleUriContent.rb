#!/usr/bin/env ruby

# object representation of a snort rule uricontent.
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'analysisEngine/SnortRuleContent'

class SnortRuleUriContent < SnortRuleContent
	attr_accessor :isdataat
	
	def to_s
		not_mod = "!" if not_modifier
		"UriContent["+ @order_number.to_s + "]:[" + not_mod.to_s + " " + unescaped_string.to_s + ", within:" + within.to_s\
		 + ", distance:" + distance.to_s + ", offset:" + offset.to_s + ", depth:" + depth.to_s\
		 + ", " + raw_bytes.to_s + ", " + nocase.to_s + ", " + isdataat.to_s + "] "
		
	end
	
	def to_r
		not_mod = "!" if not_modifier
		uri_content_str = "uricontent:" + not_mod.to_s + "\"" + unescaped_string.to_s + "\"; "
		uri_content_str = uri_content_str + "nocase; " if nocase
		uri_content_str = uri_content_str + "rawbytes; " if raw_bytes
		uri_content_str = uri_content_str + "depth:"+depth.to_s+"; " if depth
		uri_content_str = uri_content_str + "within:"+within.to_s+"; " if within
		uri_content_str = uri_content_str + "distance:"+distance.to_s+"; " if distance
		uri_content_str = uri_content_str + "offset:"+offset.to_s+"; " if offset
		uri_content_str = uri_content_str + "isdataat:" + isdataat.to_s + "; " if isdataat
		uri_content_str
	end
	
	def eql?(object)
		return self.to_s == object.to_s
	end
	
	def ==(object)
		return self.to_s == object.to_s
	end
end

require 'test/unit/testcase'

class SnortRuleUriContentTest < Test::Unit::TestCase


	#test simple case sensitive match with binary data
	def test_match_case_sensitive_binary
		#uri_content with exact match
		uri_content = "first line.\nthis string contains a case sensitive match on: MyMatch123"
		snort_rule_uri_content = SnortRuleUriContent.new
		snort_rule_uri_content.unescaped_string = "M|79|Mat|63 68|123" #equals MyMatch123
		snort_rule_uri_content.nocase = false
		
		match = snort_rule_uri_content.match(uri_content,0)
		assert_equal(60, match,"no case sensitive match on uri content.")
	end
	
	def test_to_r
		snort_rule_uri_content = SnortRuleUriContent.new
		snort_rule_uri_content.not_modifier = false
		snort_rule_uri_content.unescaped_string = "mymatch123"
		snort_rule_uri_content.nocase = true	
		snort_rule_uri_content.isdataat = 5
		
		expected_str = "uricontent:\"mymatch123\"; nocase; isdataat:5; "
		assert_equal(expected_str,snort_rule_uri_content.to_r,"To R not correct.")
	end
end

#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRuleUriContentTest)
