#!/usr/bin/env ruby

# object representation of a snort rule pcre.
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php
class SnortRulePcre
	attr_accessor :not_modifier, :regex, :modifiers, :expr, :order_no, :unescaped_regex
	
	def to_s
		not_mod = "!" if not_modifier
		"Prce["+ @order_no.to_s + "]:[" + not_mod.to_s + regex.to_s + modifiers.to_s + "]"
	end
	
	def to_r
		not_mod = "!" if not_modifier
		pcre_str = "pcre:\"" + not_mod.to_s + regex.to_s + modifiers.to_s + "\"; "
		pcre_str
	end
	
	
	def match(content, last_match)
		match = false
		
		content_section = content
		if(modifiers.index("R")!=nil)
			content_section=content[last_match..-1]
		end
		
		if (expr == nil)
			if(modifiers.index("s") && modifiers.index("i"))
				expr = Regexp.compile(regex[1..-2], (Regexp::IGNORECASE || Regexp::MULTILINE) )
			elsif modifiers.index("m")
				expr = Regexp.compile(regex[1..-2], (Regexp::MULTILINE) )
			elsif modifiers.index("i")
				expr = Regexp.compile(regex[1..-2], (Regexp::IGNORECASE) )
			else
				expr = Regexp.compile(regex[1..-2] )
			end
		end
		match = (expr =~ content_section) if expr =~ content_section
		
		if(not_modifier && match)
			return false
		elsif (not_modifier && !match)
			return 0
		else
			return match
		end
	end
	
	def eql?(object)
		return self.to_s == object.to_s
	end
	
	def ==(object)
		return self.to_s == object.to_s
	end
end



require 'test/unit/testcase'

class SnortRulePcreTest < Test::Unit::TestCase
	
	
	def test_match_R
		pcre = SnortRulePcre.new
		pcre.not_modifier= false
		pcre.regex = "/test/"
		pcre.modifiers = "R"
		assert(pcre.match("this is a test.",4),"no match on test_match_R")
	end
	
	def test_no_match_R
		pcre = SnortRulePcre.new
		pcre.not_modifier= false
		pcre.regex = "/test/"
		pcre.modifiers = "R"
		assert(!pcre.match("test is a no match.",4),"match on test_no_match_R")
	end
	
	def test_match_noR
		pcre = SnortRulePcre.new
		pcre.not_modifier= false
		pcre.regex = "/test/"
		pcre.modifiers = ""
		assert(pcre.match("test is a this.",4),"no match on test_match_noR") #if no R is specified, ignore last_match
	end
	
	def test_nomatch_case_sensitive_not_modifier
		pcre = SnortRulePcre.new
		pcre.not_modifier= true
		pcre.regex = "/test/"
		pcre.modifiers = ""
		assert(!pcre.match("this is a test.",0),"match on no_match_case_sensitive_not_modifier")
	end
	
	def test_match_case_sensitive_not_modifier
		pcre = SnortRulePcre.new
		pcre.not_modifier= true
		pcre.regex = "/test/"
		pcre.modifiers = ""
		
		match = pcre.match("this is a NO MATCH.",0)
		assert_equal(0, match,"no match on match_case_sensitive_not_modifier")
	end
	
	def test_match_case_sensitive
		pcre = SnortRulePcre.new
		pcre.not_modifier= false
		pcre.regex = "/test/"
		pcre.modifiers = ""
		
		match = pcre.match("this is a test.",0)
		assert_equal(10,match,"no match on match_case_sensitive")
	end
	
	def test_match_case_insensitive
		pcre = SnortRulePcre.new
		pcre.not_modifier= false
		pcre.regex = "/test/"
		pcre.modifiers = "i"
		
		match = pcre.match("this is a TEST.",0)
		assert_equal(10, match,"no match on match_case_insensitive")
	end
	
	def test_nomatch_case_sensitive
		pcre = SnortRulePcre.new
		pcre.not_modifier= false
		pcre.regex = "/test/"
		pcre.modifiers = ""
		assert(!pcre.match("this is a TEST.",0),"match on nomatch_case_insensitive")
	end

	def test_match_multiline
		pcre = SnortRulePcre.new
		pcre.not_modifier= false
		pcre.regex = "/test/"
		pcre.modifiers = "si"
		
		match = pcre.match("this is\n a TEST.",0)
		assert_equal(11,match,"no match on match_multiline")
	
	end
	
	def to_r
		pcre = SnortRulePcre.new
		pcre.not_modifier= false
		pcre.regex = "/te[\"]st/"
		pcre.modifiers = "si"
		
		expected_str = "pcre:\"/te[\"]st/si\""
		assert_equal(expected_str,pcre.to_r,"To r not correct.")
	end
end

#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRulePcreTest)

