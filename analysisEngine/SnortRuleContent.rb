#!/usr/bin/env ruby

# object representation of a snort rule content.
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php
class SnortRuleContent
	attr_accessor :unescaped_string, :nocase, :not_modifier, :depth, :offset, :distance, :within, :raw_bytes, :order_no
	
	def initialize() 
		not_modifier = false
		nocase = false
	end
	
	def unescaped_string=(unesc_str)
		@unescaped_string = unesc_str
		if(unesc_str.index("|") && unesc_str.index("|")>0) 
			@unescaped_string_without_bin = unesc_str[0..unesc_str.index("|")-1]
		elsif(unesc_str.index("|") && unesc_str.index("|")==0)
			@unescaped_string_without_bin = ""
		else
			@unescaped_string_without_bin = unesc_str
		end
		
		binary = true
		unesc_str.scan(/[\|][^\|]*[^\|]/) { |bin_str|
			if binary 
				#convert binary hex pairs into string representatives 
				bin_str[1..-1].scan(/[0-9ABCDEFabcdef][0-9ABCDEFabcdef]/) { |bin_pair|
					@unescaped_string_without_bin << bin_pair.hex	
				}
			else
				@unescaped_string_without_bin = @unescaped_string_without_bin + bin_str[1..-1]
			end
			#puts bin_str
			binary = !binary
		}
	end
	
	#externally facing function
	def match(content, last_match)
		match = false
		
		content_section = content
		if(offset!=nil || depth!=nil)
			if(offset!=nil && depth!=nil)
				content_section = content[offset..depth-1]
			elsif (offset!=nil)
				content_section = content[offset..-1]
			elsif (depth!=nil)
				content_section = content[0..depth-1]
			else
				content_section = content
			end
		elsif (distance!=nil || within!=nil)
			if(distance!=nil && within!=nil)
				content_section = content[distance+last_match..within-1]
			elsif (distance!=nil)
				content_section = content[distance+last_match..-1]
			elsif (within!=nil)
				content_section = content[0..within-1]
			else
				content_section = content
			end
		
		else
			content_section = content
		end
		
		if !nocase
			regex = Regexp.compile(Regexp.escape(@unescaped_string_without_bin), (Regexp::MULTILINE))
			match = (regex =~ content_section) if regex =~ content_section
		else
			regex = Regexp.compile(Regexp.escape(@unescaped_string_without_bin), (Regexp::IGNORECASE || Regexp::MULTILINE) )
			match = (regex =~ content_section) if regex =~ content_section
		end
		
		if(not_modifier && match)
			return false
		elsif (not_modifier && !match)
			return 0
		else
			if(match && offset)
				return match + offset
			elsif(match && distance)
				return match + distance + last_match
			elsif(match && within)
				return match + last_match
			else
				return match
			end
		end
		
		return match
	end

	def SnortRuleContent.unescape(escaped_str)
		#replace \\ with \
		#replace \: with :
		#replace \; with ;
		while(escaped_str.sub(/\\\"/, "\"")!=escaped_str)
			escaped_str.sub!("\\\"","\"")
		end
		while(escaped_str.sub(/\\:/, ":")!=escaped_str)
			escaped_str.sub!("\\:",":")
		end
		while(escaped_str.sub(/\\;/, ";")!=escaped_str)
			escaped_str.sub!("\\;",";")
		end		
		while(escaped_str.sub(/\\\\/, "\\")!=escaped_str)
			escaped_str.sub!(/\\\\/,"\\")
		end
		return escaped_str
	end	

	def SnortRuleContent.escape(unescaped_string)
		while(/[^\\]\\[^"\\]/=~unescaped_string)
			#STDERR.puts "1"
			#STDERR.puts Regexp.last_match
			#STDERR.puts unescaped_string
			unescaped_string = Regexp.last_match.pre_match.to_s + Regexp.last_match.to_s[0].chr+"\\\\"+Regexp.last_match.to_s[-1].chr+Regexp.last_match.post_match.to_s
		end
		while(/[^\\]\"/=~unescaped_string)
			#STDERR.puts "2"
			#STDERR.puts Regexp.last_match
			#STDERR.puts unescaped_string.to_s
			unescaped_string = unescaped_string.sub(/[^\\]\"/,Regexp.last_match.to_s[0].chr+"\\\"") 	
		end
		while(/[^\\]:/=~unescaped_string)
			#STDERR.puts "3"
			#STDERR.puts Regexp.last_match
			#STDERR.puts unescaped_string
			unescaped_string = unescaped_string.sub(/[^\\]:/,Regexp.last_match.to_s[0].chr+"\\:") 	
		end
		while(/[^\\];/=~unescaped_string)
			#STDERR.puts "4"
			#STDERR.puts Regexp.last_match
			#STDERR.puts unescaped_string
			unescaped_string = unescaped_string.sub(/[^\\];/,Regexp.last_match.to_s[0].chr+"\\;") 	
		end
		escaped_string = unescaped_string
		return escaped_string

	end
		
	def has_binary?
		if(!unescaped_string.index("|"))
			return false
		else 
			return true
		end
	end
	
	def permutable?
		clean_str = !has_binary?
		no_modifiers = (!nocase && (distance==nil) && (offset==nil) && (depth==nil) && (within==nil))
		return clean_str && no_modifiers
	end
	
	def to_s
		not_mod = "!" if not_modifier
		"Content["+ @order_no.to_s + "]:[" + not_mod.to_s + " " + SnortRuleContent.escape(unescaped_string.to_s) + ", within:" + within.to_s\
		 + ", distance:" + distance.to_s + ", offset:" + offset.to_s + ", depth:" + depth.to_s\
		 + ", " + raw_bytes.to_s + ", " + nocase.to_s + "] "
		
	end
	
	def to_r
		not_mod = "!" if not_modifier
		content_str = "content:" + not_mod.to_s + "\"" + SnortRuleContent.escape(unescaped_string.to_s) + "\"; "
		content_str = content_str + "nocase; " if nocase
		content_str = content_str + "rawbytes; " if raw_bytes
		content_str = content_str + "depth:"+depth.to_s+"; " if depth
		content_str = content_str + "within:"+within.to_s+"; " if within
		content_str = content_str + "distance:"+distance.to_s+"; " if distance
		content_str = content_str + "offset:"+offset.to_s+"; " if offset
		content_str
	end
	
	def eql?(object)
		return self.to_s == object.to_s
	end
	
	def ==(object)
		return self.to_s == object.to_s
	end
end

require 'test/unit/testcase'

class SnortRuleContentTest < Test::Unit::TestCase
	def test_permutable_with_binary
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "test|3a|test"
		snort_rule_content.nocase = false
		
		assert(!snort_rule_content.permutable?,"non permutable binary content.")
	end
	
	def test_permutable_with_nocase
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "test"
		snort_rule_content.nocase = true
		
		assert(!snort_rule_content.permutable?,"non permutable case insensitive content.")
	end
	
	def test_permutable_with_nocase
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "test"
		snort_rule_content.within = 3
		
		assert(!snort_rule_content.permutable?,"non permutable content with within.")
	end
	
	def test_permutable
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "test"
		
		assert(snort_rule_content.permutable?,"clean content tagged as non permutable.")
	end

	def test_has_binary_true
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "test|3a|test"
		snort_rule_content.nocase = true
		
		assert(snort_rule_content.has_binary?,"binary content not detected.")
	end
	
	def test_has_binary_false
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "test"
		snort_rule_content.nocase = true
		
		assert(!snort_rule_content.has_binary?,"binary content incorrectly detected.")
	end

	#test simple case sensitive match with binary data
	def test_match_case_sensitive_special_char
		#content with exact match
		content = "first line.\nthis string contains a case sensitive match on: My(Match123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "My(Match123" 
		snort_rule_content.nocase = false
		
		match = snort_rule_content.match(content,0)
		assert_equal(60, match,"no case sensitive match on content with special char.")
	end
	
	def test_match_case_sensitive_binary
		#content with exact match
		content = "first line.\nthis string contains a case sensitive match on: MyMatch123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "M|79|Mat|63 68|123" #equals MyMatch123
		snort_rule_content.nocase = false
		match = snort_rule_content.match(content,0)
		assert_equal(60, match,"no case sensitive match on content.")
	end

#test simple case without match with binary data
	def test_match_case_sensitive_binary_no_match
		#content with exact match
		content = "first line.\nthis string doesnt contains a match on: My"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "M|79|Mat|63 68|123" #equals MyMatch123
		snort_rule_content.nocase = false
		assert(!snort_rule_content.match(content,0),"case sensitive match on no match content.")
	end

	def test_match_case_sensitive_binary_no_match_start_bin
		#content with exact match
		content = "first line.\nthis string doesnt contains y 79 match on: MMat"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "|79|Mat|79|M" #equals MyMatch123
		snort_rule_content.nocase = false
		assert(!snort_rule_content.match(content,0),"case sensitive match on no match content.")
	end
	
	#test simple case sensitive match with distance
	def test_match_case_sensitive_distance
		#content with exact match
		content = "123MyMatch123MyMatch"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch"
		snort_rule_content.distance = 1
		snort_rule_content.nocase = false
		match = snort_rule_content.match(content,4)
		assert_equal(13, match,"no match on content with distance.") #13 position of second MyMatch
	end
	
	#test overflow scenario
	def test_bug_1623202
		#content with exact match
		content = "xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"\
			+"xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]xx]"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "]"
		snort_rule_content.distance = 0
		snort_rule_content.nocase = false
		match = snort_rule_content.match(content,0)
		assert_equal(2, match,"no match on content with distance.") 
	end

	#test simple case sensitive match with depth
	def test_match_case_sensitive_distance_no_match
		#content with exact match
		content = "123MyMatch123MyMatch"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch"
		snort_rule_content.distance = 11
		snort_rule_content.nocase = false
		assert(!snort_rule_content.match(content,4),"incorrect match on content with distance.")
	end
	
	#test simple case sensitive match with depth
	def test_match_case_sensitive_depth
		#content with exact match
		content = "123MyMatch and some more"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch"
		snort_rule_content.depth = 10
		snort_rule_content.nocase = false
		match = snort_rule_content.match(content,0)
		assert_equal(3, match,"no match on content with depth.")
	end
	
	#test simple case sensitive no match with depth
	def test_match_case_sensitive_depth_no_match
		#content with exact match
		content = "123MyMatch and some more"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch"
		snort_rule_content.depth = 9
		snort_rule_content.nocase = false
		assert(!snort_rule_content.match(content,0),"incorrect match on content with depth.")
	end
	
	#test simple case sensitive match with within
	def test_match_case_sensitive_within
		#content with exact match
		content = "123MyMatch123MyMatch"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch"
		snort_rule_content.within = 10
		snort_rule_content.nocase = false
		match = snort_rule_content.match(content,10)
		assert_equal(13, match,"no match on content with within.") #13 pos of second MyMatch
	end

	#test simple case sensitive match with within
	def test_match_case_sensitive_within_no_match
		#content with exact match
		content = "1234MyMatch123MyMatch"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch"
		snort_rule_content.within = 10
		snort_rule_content.nocase = false
		assert(!snort_rule_content.match(content,0),"incorrect match on content with within.")
	end

	#test simple case sensitive match with offset
	def test_match_case_sensitive_offset
		#content with exact match
		content = "123MyMatch and some more"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch"
		snort_rule_content.offset = 3
		snort_rule_content.nocase = false
		match = snort_rule_content.match(content,0)
		assert_equal(3, match,"no match on content with offset.")
	end

	#test simple case sensitive match with offset
	def test_match_case_sensitive_offset_no_match
		#content with exact match
		content = "123MyMatch and some more"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch"
		snort_rule_content.offset = 4
		snort_rule_content.nocase = false
		assert(!snort_rule_content.match(content,0),"incorrect match on content with offset.")
	end
	
	#test simple case sensitive match
	def test_match_case_sensitive
		#content with exact match
		content = "first line.\nthis string contains a case sensitive match on: MyMatch123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch123"
		snort_rule_content.nocase = false
		match = snort_rule_content.match(content,0)
		assert_equal(60, match,"no case sensitive match on content.")
	end
	
	#test simple case sensitive match without a match
	def test_match_case_sensitive_no_match
		#content with case insensitive, but not case sensitive match
		content = "first line.\nthis string doesn not contain a case insensitive match on: mymatch123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "MyMatch123"
		snort_rule_content.nocase = false
		assert(!snort_rule_content.match(content,0),"incorrect case sensitive match on content.")
	end
	
	#test simple nocase match
	def test_match_nocase
		#content with exact match
		content = "first line.\nthis string contains a case insensitive match on: MyMatch123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "mymatch123"
		snort_rule_content.nocase = true
		match = snort_rule_content.match(content,0)
		assert_equal(62, match,"no case insensitive match on content.")
	end
	
	def test_match_nocase_no_match
		content = "first line.\nthis string does not contain a case insensitive match on: MyMatch123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.unescaped_string = "some other string"
		snort_rule_content.nocase = true
		assert(!snort_rule_content.match(content,0),"incorrect case insensitive match on content.")	
	end
	
	#test not modifier with nocase match
	def test_exclusion_match_nocase
		content = "first line.\nthis string contains a case insensitive match on: MyMatch123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.not_modifier = true
		snort_rule_content.unescaped_string = "mymatch123"
		snort_rule_content.nocase = true
		assert(!snort_rule_content.match(content,0),"incorrect nocase exclusion match on content.")
	end
	
	#test not modifier with case sensitive match
	def test_exclusion_match
		content = "first line.\nthis string contains a case sensitive match on: MyMatch123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.not_modifier = true
		snort_rule_content.unescaped_string = "MyMatch123"
		snort_rule_content.nocase = false
		assert(!snort_rule_content.match(content,0),"incorrect case sensitive exclusion match on content.")
	end

	#test not modifier without nocase match. so this one should fire.
	def test_exclusion_match_nocase_no_match
		content = "first line.\nthis string does not contain a case insensitive match on: MyMatch123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.not_modifier = true
		snort_rule_content.unescaped_string = "some other string"
		snort_rule_content.nocase = true
		match = snort_rule_content.match(content,0)
		assert_equal(0, match,"nocase exclusion match on content didnt fire.")	
	end
	
	#test not modifier without case sensitive match. so this one should fire.
	def test_exclusion_match_nocase
		content = "first line.\nthis string does not contain a case sensitive match on: MyMatch123"
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.not_modifier = true
		snort_rule_content.unescaped_string = "mymatch123"
		snort_rule_content.nocase = false
		match = snort_rule_content.match(content,0)
		assert_equal(0, match,"case sensitive exclusion match on content didnt fire.")	
	end
	
	def test_to_r
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.not_modifier = true
		snort_rule_content.unescaped_string = "mymatch123"
		snort_rule_content.nocase = false	
		snort_rule_content.depth = 5
		snort_rule_content.within=10
		
		expected_str = "content:!\"mymatch123\"; depth:5; within:10; "
		assert_equal(expected_str,snort_rule_content.to_r,"To R not correct.")
	end

	def test_to_r_escaped_quote
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.not_modifier = true
		snort_rule_content.unescaped_string = "mym\"atch123"
		snort_rule_content.nocase = false	
		snort_rule_content.depth = 5
		snort_rule_content.within=10
		
		expected_str = "content:!\"mym\\\"atch123\"; depth:5; within:10; "
		assert_equal(expected_str,snort_rule_content.to_r,"To R not correct.")
	end

	def test_to_r_escaped_doubleslash
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.not_modifier = true
		snort_rule_content.unescaped_string = "mym\\atch123"
		snort_rule_content.nocase = false	
		snort_rule_content.depth = 5
		snort_rule_content.within=10
		
		expected_str = "content:!\"mym\\\\atch123\"; depth:5; within:10; "
		assert_equal(expected_str,snort_rule_content.to_r,"To R not correct.")
	end

	def test_to_r_escaped_column
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.not_modifier = true
		snort_rule_content.unescaped_string = "mym:atch123"
		snort_rule_content.nocase = false	
		snort_rule_content.depth = 5
		snort_rule_content.within=10
		
		expected_str = "content:!\"mym\\:atch123\"; depth:5; within:10; "
		assert_equal(expected_str,snort_rule_content.to_r,"To R not correct.")
	end

	def test_to_r_escaped_negtest
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.not_modifier = true
		snort_rule_content.unescaped_string = "mym\:atch123"
		snort_rule_content.nocase = false	
		snort_rule_content.depth = 5
		snort_rule_content.within=10
		
		expected_str = "content:!\"mym\\:atch123\"; depth:5; within:10; "
		assert_equal(expected_str,snort_rule_content.to_r,"To R not correct.")
	end

end

#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRuleContentTest)
