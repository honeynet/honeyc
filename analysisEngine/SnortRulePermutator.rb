#!/usr/bin/env ruby

# The SnortRulePermutator permutates existing Snort rules to counter obfuscation 
# attempts by the bad guys. While the encoding is quite basic and will not catch
# more sophisticated obfucation attempts, it will pick some low hanging fruit. You
# are using a signature based detection algorithm after all ;)
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require "net/http"
require "uri"
require "analysisEngine/SnortRuleParser.tab"

class SnortRulePermutator
	attr_accessor :rules_orig
	
	def initialize(rules_file)
		STDIN.sync=true
		
		snort_rule_parser = SnortRuleParser.new
		@rules_orig = snort_rule_parser.parse_rules(rules_file)
	end
	
	def case_insensitize_rules(rules)
		#first pass create permutations of case if case insensitive values
		#are encountered. this is necessary as the encoded value can not be
		#case insensitive. e.g. testString would be used in its original form,
		#lower case and upper case. Certainly this is not a true translation
		#of case insensitivity, but otherwise we would blow up the number of
		#rules to unmanagable levels.
		case_insensitive_rules = Array.new
		rules.each {|rule|
			STDERR.puts "case insensitize:"+rule.sid.to_s
			case_insensitive_content = 0
			rule.contents.each { | content |
				case_insensitive_content = case_insensitive_content + 1 if(content.nocase)
			}
			if(case_insensitive_content>0) #we have some
				permutations = 2**case_insensitive_content #how many new rules do we need
				
				#here we dont mix lower and upper. assuming attacker either puts everything
				#in upper or lower case. limits the number of generated rules
				#so Ab;nc,bC,Cd;nc
				#results in ab,bC,cd - ab,bC,Cd - Ab,bC,Cd for lower
				#results in AB,bC,CD - AB,bC,Cd - AB,bC,CD for upper
				#results in Ab,bC,cD for original
				rule_clone_original = rule.deep_clone
				rule_clone_original.contents.each { |content|
					content.nocase = false
				}
				case_insensitive_rules.push(rule_clone_original)
				
	
				upper_case_rules = case_insensitize_rule(rule, permutations-1, "upper")
				case_insensitive_rules = case_insensitive_rules + upper_case_rules
	
				#lower case rules
				lower_case_rules = case_insensitize_rule(rule, permutations-1, "lower")
				case_insensitive_rules = case_insensitive_rules + lower_case_rules
			else #we dont have any - we just use original rule
				##STDERR.puts "PUSH RULE " + rule.sid.to_s
				case_insensitive_rules.push(rule)
			end
		}
		##STDERR.puts "Rules Size: " + case_insensitive_rules.size.to_s
		return return_uniq_obj(case_insensitive_rules)
	end

	#I know...very inefficient...
	def return_uniq_obj(objects)
		unique_objects = Array.new
		index = 0
		objects.each { |object|
			tindex = 0
			dup_exists = false
			objects.each { |tobject|
				if(tindex>index)
					
					if(object.to_r==tobject.to_r)
						#STDERR.puts "Dupe"
					
						dup_exists = true
					end
				end
				tindex+=1
			}
			unique_objects.push(object) if !dup_exists
			index+=1
		}
		return unique_objects
	end
	
	def case_insensitize_rule(rule, permutations, rule_content_case) 
		new_rules = Array.new
		(1..permutations).each do | current_permutation |
			rule_clone = rule.deep_clone
			binary_map = current_permutation.to_s(2);
			index = permutations.to_s(2).length-binary_map.length #skip leading 0's
			
			#if content at location is case sensitive skip to next one
			while(index<permutations.to_s(2).length && !rule_clone.contents[index].nocase)
				index = index + 1
			end
			binary_map.each_byte { |current_byte|
				if(current_byte == 49) #'1'
					#encode this piece of content
					if(rule_clone.contents[index].nocase)
						current_content = rule_clone.contents[index].unescaped_string.to_s
						new_content = current_content
						if(rule_content_case=="lower")
							new_content = current_content.downcase
						elsif(rule_content_case=="upper")
							new_content = current_content.upcase
						end
						rule_clone.contents[index].unescaped_string = new_content
						rule_clone.contents[index].nocase = false
						
						rule_clone.pcres.each { |pcre|
							pcre.expr=nil
							old_regex_string = Regexp.compile(pcre.regex).source
							pcre.regex = new_regex(current_content, new_content, old_regex_string)
						}
						
						index = index + 1
					end
					#continue to skip ahead if binary content
					while(index<permutations.to_s(2).length && !rule_clone.contents[index].nocase)
						index = index + 1
					end
				else
					rule_clone.contents[index].nocase = false 
					index = index + 1
				end
			}
			
			rule_clone.contents.each { |content|
				content.nocase = false
			}
			new_rules.push(rule_clone)
		end
		##STDERR.puts new_rules.to_a
		return new_rules
	end

	def content_escape(unescaped_content_string)
		while(/[^\\]\"/=~unescaped_content_string)
			unescaped_content_string = unescaped_content_string.sub(/[^\\]\"/,Regexp.last_match.to_s[0].chr+"\\\"") 	
		end
		while(/[^\\]:/=~unescaped_content_string)
			unescaped_content_string = unescaped_content_string.sub(/[^\\]:/,Regexp.last_match.to_s[0].chr+"\\:") 	
		end
		while(/[^\\];/=~unescaped_content_string)
			unescaped_content_string = unescaped_content_string.sub(/[^\\];/,Regexp.last_match.to_s[0].chr+"\\;") 	
		end
		escaped_string = unescaped_content_string
		return escaped_string 
	end


	#c:test r:test
	#c:te(st r:te\(st
	#c:te\"st r:te\"st
	#c:te\:st r:te:st
	#c:te-st r:te-st						
	def new_regex(old_unescaped_content, new_unescaped_content, old_regex_string)
		#STDERR.puts ""
		#STDERR.puts "OldRegex" + old_regex_string
		#content already content unescaped, so it only te\:st is alreadt te:st
		
		#escape content
		#STDERR.puts SnortRuleContent.escape(old_unescaped_content)
		old_escaped_content = content_escape(Regexp.escape(old_unescaped_content))
		new_escaped_content = content_escape(Regexp.escape(new_unescaped_content))
		#STDERR.puts "OldEC:" + old_escaped_content
		#STDERR.puts "NewEC:" + new_escaped_content
	
		#fix up incorrect escape of hyphen
		while(old_escaped_content.sub("\\-","-") != old_escaped_content)
			old_escaped_content = old_escaped_content.sub("\\-","-") 
		end
		while(new_escaped_content.sub("\\-","-") != new_escaped_content)
			new_escaped_content = new_escaped_content.sub("\\-","-") 
		end

		#replace all occurences of old_escaped_content with new_escaped_content in old_regex_string
		while(old_regex_string.sub(old_escaped_content,new_escaped_content) !=old_regex_string)
			old_regex_string = old_regex_string.sub(old_escaped_content,new_escaped_content) 
		end
		new_regex_string = old_regex_string
		#STDERR.puts "NewRegex" + new_regex_string
		return new_regex_string
	end
	
	def encode_rules(rules, start_sid, encoding_type)
		encoded_rules = Array.new
		rules.each { |rule|
			STDERR.puts "encode:"+rule.sid.to_s
			permutable_content = 0
			rule.contents.each { | content |
				permutable_content = permutable_content + 1 if(content.permutable?)
			}
			
			permutations = 2**permutable_content #how many new rules do we need
			
			#STDERR.puts "perm2:" + permutations.to_s
			encoded_rules = encoded_rules + encode_rule(rule, permutations-1, start_sid, encoding_type)
			start_sid = start_sid.to_i + (permutations-1)
		}
		return return_uniq_obj(encoded_rules)
	end
	
	
	#generates bin representation of array of content
	#encoded where a one occurs
	#e.g. 0101 encodes content array of length 4 at position 1 and 3.
	def encode_rule(rule, permutations,start_sid, encoding_type)
		encoded_rule = Array.new
		(1..permutations).each do | current_permutation |
			rule_clone = rule.deep_clone
			rule_clone.msg = rule.msg.to_s + " - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID " + rule.sid.to_s
			rule_clone.sid = start_sid
			start_sid = start_sid.to_i+1
			
			binary_map = current_permutation.to_s(2);
			#STDERR.puts "BinMap2: " + binary_map.to_s
			
			#if index is one, encode
			#if content at position is binary skip to next one
			index = permutations.to_s(2).length-binary_map.length #skip leading zeros (e.g. 0001, it goes to pos of 1)
			while(index<permutations.to_s(2).length && !rule_clone.contents[index].permutable?)
				index = index + 1
			end
			binary_map.each_byte { |current_byte|
				if(current_byte == 49) #'1'
					#STDERR.puts "Index2 " + index.to_s
					#encode this piece of content
					if(rule_clone.contents[index].permutable?)
						current_content = rule_clone.contents[index].unescaped_string.to_s
						new_content = ""
						case encoding_type
						when "toCharCode"
							current_content.each_byte { |b| 
								new_content << b.to_i.to_s
								new_content << ','
							}
							new_content = new_content[0..-2]
							
						when "unicodeEncode"
							current_content.each_byte { |b| 
								new_content << '%u00'
								new_content << b.to_i.to_s(16)
							}
						when "hexEncode"
							current_content.each_byte { |b| 
								new_content << '%'
								new_content << b.to_i.to_s(16)
							}
						when "uuencode"
							arr = Array.new
							arr.push(current_content)
							new_content=  arr.pack("u").to_s[1..-2]
						else
							raise "Encoding type " + encoding_type.to_s + " not recognized."
						end
						rule_clone.contents[index].unescaped_string = SnortRuleContent.unescape(new_content)
						rule_clone.pcres.each { |pcre|
							pcre.expr=nil
							old_regex_string = Regexp.compile(pcre.regex).source
							pcre.regex = new_regex(current_content, new_content, old_regex_string)
						}
						index = index + 1
					end
					#continue to skip ahead if binary content
					while(index<permutations.to_s(2).length && (!rule_clone.contents[index].permutable?))
						index = index + 1
					end
				else
					index = index + 1
				end
			}
			encoded_rule.push(rule_clone)
		end
		return encoded_rule
	end

end

#public static void main?
if ARGV.length==1 and ARGV[0]=="--help"
	STDERR.puts "Usage: ruby analysisEngine/SnortRulePermutator.rb [location of snort rules] "
	STDERR.puts "[start_new_sid] [encoding type]"
	STDERR.puts "Permutates existing Snort rules."
	STDERR.puts ""
	STDERR.puts "The SnortRulePermutator permutates existing Snort rules to counter obfuscation "
	STDERR.puts "attempts by the bad guys. It inputs existing snort rules, encodes each "
	STDERR.puts "content value, and outputs a new Snort Rule with this encoded content "
	STDERR.puts "value. If there are multiple content values, the SnortRulePermutator will "
	STDERR.puts "output several new rules of which content is selectively encoded. "
	STDERR.puts "For example, lets assume two content values exists, the permutator will "
	STDERR.puts "output three rules: first content value encoded, second content value "
	STDERR.puts "untouched; first content value untouched, second content value encoded; and "
	STDERR.puts "first content value uuencoded, second content value uuencoded. Currently only "
	STDERR.puts "content values that do not contain any binary data are permutated."
	STDERR.puts "If a pcre is mixed in with the rule it is usually untouched as part of the "
	STDERR.puts "permutation and is simply output unmodified. However, if a content string is"
	STDERR.puts "a substring of the pcre, its value is replaced as part of the pcre. For "
	STDERR.puts "example, content test and pcre .*test.*, the string test would be replaced "
	STDERR.puts "with the permutated value in the pcre."
	STDERR.puts "On content values that are case insensitive, the permutator creates three "
	STDERR.puts "sets of rules with different case for the content (original, lower case and "
	STDERR.puts "caps, which are then permutated according to the rules above."
	STDERR.puts "There are several encoding types supported. However, with the assumption that a"
	STDERR.puts "bad guy only uses one method, only one encoding type can be applied. If this "
	STDERR.puts "is not followed, it would lead to an explosion of generated snort rules."
	STDERR.puts ""
	STDERR.puts ""
	STDERR.puts "Parameters:"
	STDERR.puts "location of snort rules  - the initial set of snort rules that should be "
	STDERR.puts "                           permutated."
	STDERR.puts "start new sid            - the sid that the generated rules should start with. "
	STDERR.puts "                           value is incremented by one for each rule"
	STDERR.puts "encoding type            - the type of encoding that should be applied."
	STDERR.puts "				Currently, supported is uuencode, toCharCode, "
	STDERR.puts "				hexEncode, unicodeEncode."	
	STDERR.puts "				uuencode - applies uuencoding. test -> $=&5S=```"
	STDERR.puts "				toCharCode - creates a comma separated list of "
	STDERR.puts "					the char codes. test -> 116,101,115,116"
	STDERR.puts "				hexEncode - creates a % separated list of "
	STDERR.puts "					the char codes in hex. test -> %74%65%73%74"
	STDERR.puts "				unicodeEncode - creates a %u separated list of "
	STDERR.puts "					the char codes in unicode."
	STDERR.puts " 					test -> %u0074%u0065%u0073%u0074"
	STDERR.puts ""
	STDERR.puts ""
	STDERR.puts "Report bugs to <https://bugs.honeynet.org/enter_bug.cgi?product=Honey-C>"
elsif ARGV.length==0
	STDERR.puts "Usage: ruby analysisEngine/SnortRulePermutator.rb [location of snort rules] "
	STDERR.puts "[start_new_sid] [encoding type]"
	STDERR.puts "Try 'ruby analysisEngine/SnortRulePermutator.rb --help' for more information."
else
	snortRulePermutator = SnortRulePermutator.new(ARGV[0])
	case_insensitive_rules = snortRulePermutator.case_insensitize_rules(snortRulePermutator.rules_orig)
	encoded_rules = snortRulePermutator.encode_rules(case_insensitive_rules,ARGV[1], ARGV[2])
	encoded_rules.each{ |rule| 
		STDERR.puts "Outputting rule " + rule.sid.to_s
		puts rule.to_r }
end

require 'test/unit/testcase'
require 'stringio'
# Basic unit test for SnortRulePermutator class
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php
class SnortRulePermutatorTest < Test::Unit::TestCase
	
	
	
	def test_permutation_pcre_replacement
		permutator = SnortRulePermutator.new("analysisEngine/permutatorUnittest3.rules")
		case_insensitive_rules = permutator.case_insensitize_rules(permutator.rules_orig)
		new_actual_rules = permutator.encode_rules(case_insensitive_rules,100, "hexEncode")
		new_actual_rules_string = ""
		new_actual_rules.each { |rule| 
			new_actual_rules_string = new_actual_rules_string + rule.to_r
		} 
		
		new_expected_rules = "alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"100; rev:4; classtype:trojan-activity; priority:10; content:\"%74%65%22%73%74\"; pcre:"\
			+"\"/.*%74%65%22%73%74.*/i\"; )"\
			+ "alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule2 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000002\"; sid:"\
			+"101; rev:4; classtype:trojan-activity; priority:10; content:\"%74%65%28%73%74\"; pcre:"\
			+"\"/.*%74%65%28%73%74.*/i\"; )"\
			+ "alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule3 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000003\"; sid:"\
			+"102; rev:4; classtype:trojan-activity; priority:10; content:\"%74%65%28%73%74\"; pcre:"\
			+"\"/.*%74%65%28%73%74s\\)t%74%65%28%73%74.*/i\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule4 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000004\"; sid:"\
			+"103; rev:4; classtype:trojan-activity; priority:10; "\
			+"content:\"%30%36%44%44%33%38%44%33%2d%44%31%38%37%2d%31%31%43%46%2d%41%38%30%44%2d%30%30%43%30%34%46%44%37%34%41%44%38\";"\
			+" pcre:\"/<OBJECT\\s+[^>]*classid\\s*=\\s*[\\x22\\x27]?\\s*clsid\\s*\\x3a\\s*\\x7B?"\
			+"\\s*%30%36%44%44%33%38%44%33%2d%44%31%38%37%2d%31%31%43%46%2d%41%38%30%44%2d%30%30%43%30%34%46%44%37%34%41%44%38/i\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $"\
			+ "EXTERNAL_NET $HTTP_PORTS (msg:\"rule4 msg - Generated by SnortRulePermutator bas"\
			+ "ed on SID - Generated by SnortRulePermutator based on SID 1000004\"; sid:104; re"\
			+ "v:4; classtype:trojan-activity; priority:10; content:\"%30%36%64%64%33%38%64%33%"\
			+ "2d%64%31%38%37%2d%31%31%63%66%2d%61%38%30%64%2d%30%30%63%30%34%66%64%37%34%61%64"\
			+ "%38\"; pcre:\"/<OBJECT\\s+[^>]*classid\\s*=\\s*[\\x22\\x27]?\\s*clsid\\s*\\x3a\\"\
			+ "s*\\x7B?\\s*%30%36%64%64%33%38%64%33%2d%64%31%38%37%2d%31%31%63%66%2d%61%38%30%64%2d%30%30%63%30%34%66%64%37%34%61%64%38/i\"; )"
			
		assert_equal(new_expected_rules,new_actual_rules_string,"Permutator did not generate expected hexEncode rules.")
	end
	
	
	def test_permutation_case_multiple
		
		permutator = SnortRulePermutator.new("analysisEngine/permutatorUnittest5.rules")
		new_actual_rules = permutator.case_insensitize_rules(permutator.rules_orig)
		new_actual_rules_string = ""
		new_actual_rules.each { |rule| 
			new_actual_rules_string = new_actual_rules_string + rule.to_r
		}
		
		new_expected_rules = "alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg\"; "\
			+"sid:1000001; rev:4; classtype:trojan-activity; priority:10; content:\"test\"; content:\"TESTTHIS\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg\"; "\
			+"sid:1000001; rev:4; classtype:trojan-activity; priority:10; content:\"TEST\"; content:\"testThis\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg\"; "\
			+"sid:1000001; rev:4; classtype:trojan-activity; priority:10; content:\"TEST\"; content:\"TESTTHIS\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg\"; "\
			+"sid:1000001; rev:4; classtype:trojan-activity; priority:10; content:\"test\"; content:\"testThis\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg\"; "\
			+"sid:1000001; rev:4; classtype:trojan-activity; priority:10; content:\"test\"; content:\"testthis\"; )"
			
			
		assert_equal(new_expected_rules,new_actual_rules_string,"Permutator did not generate expected case insensitive rules.")
	end

	def test_permutation_case
		permutator = SnortRulePermutator.new("analysisEngine/permutatorUnittest4.rules")
		new_actual_rules = permutator.case_insensitize_rules(permutator.rules_orig)
		new_actual_rules_string = ""
		new_actual_rules.each { |rule| 
			new_actual_rules_string = new_actual_rules_string + rule.to_r
		}
		
		new_expected_rules = "alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg\"; "\
			+"sid:1000001; rev:4; classtype:trojan-activity; priority:10; content:\"testThis\""\
			+"; )alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg\"; "\
			+"sid:1000001; rev:4; classtype:trojan-activity; priority:10; content:\"TESTTHIS"\
			+"\"; )alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg\""\
			+"; sid:1000001; rev:4; classtype:trojan-activity; priority:10; content:\"testthis"\
			+"\"; )alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule2 msg"\
			+"\"; sid:1000002; rev:4; classtype:trojan-activity; priority:10; content:\"testThi"\
			+"s\"; pcre:\"/.*testThis.*/i\"; )alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $H"\
			+"TTP_PORTS (msg:\"rule2 msg\"; sid:1000002; rev:4; classtype:trojan-activity; pri"\
			+"ority:10; content:\"TESTTHIS\"; pcre:\"/.*TESTTHIS.*/i\"; )alert tcp !$HOME_NET "\
			+"!80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule2 msg\"; sid:1000002; rev:4; cla"\
			+"sstype:trojan-activity; priority:10; content:\"testthis\"; pcre:\"/.*testthis.*/"\
			+"i\"; )alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule3 msg"\
			+"\"; sid:1000003; rev:4; classtype:trojan-activity; priority:10; content:\"testOn"\
			+"lyThis\"; )"
		assert_equal(new_expected_rules,new_actual_rules_string,"Permutator did not generate expected hexEncode rules.")
	end

	def test_permutation_toCharCode_one_content_field
		permutator = SnortRulePermutator.new("analysisEngine/permutatorUnittest2.rules")
		case_insensitive_rules = permutator.case_insensitize_rules(permutator.rules_orig)
		new_actual_rules = permutator.encode_rules(case_insensitive_rules,100, "toCharCode")
		new_actual_rules_string = ""
		new_actual_rules.each { |rule| 
			new_actual_rules_string = new_actual_rules_string + rule.to_r
		} 
		
		new_expected_rules = "alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"100; rev:4; classtype:trojan-activity; priority:10; content:\"116,101,115,116\"; uriconte"\
			+"nt:\"uri content\"; )"
			
		assert_equal(new_expected_rules,new_actual_rules_string,"Permutator did not generate expected toCharCode rules.")
	end
	
	def test_permutation_hexEncoded_one_content_field
		permutator = SnortRulePermutator.new("analysisEngine/permutatorUnittest2.rules")
		case_insensitive_rules = permutator.case_insensitize_rules(permutator.rules_orig)
		new_actual_rules = permutator.encode_rules(case_insensitive_rules,100, "hexEncode")
		new_actual_rules_string = ""
		new_actual_rules.each { |rule| 
			new_actual_rules_string = new_actual_rules_string + rule.to_r
		} 
		new_expected_rules = "alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"100; rev:4; classtype:trojan-activity; priority:10; content:\"%74%65%73%74\"; uriconte"\
			+"nt:\"uri content\"; )"
			
		assert_equal(new_expected_rules,new_actual_rules_string,"Permutator did not generate expected hexEncode rules.")
	end
	
	def test_permutation_unicodeEncoded_one_content_field
		permutator = SnortRulePermutator.new("analysisEngine/permutatorUnittest2.rules")
		case_insensitive_rules = permutator.case_insensitize_rules(permutator.rules_orig)
		new_actual_rules = permutator.encode_rules(case_insensitive_rules,101, "unicodeEncode")
		new_actual_rules_string = ""
		new_actual_rules.each { |rule| 
			new_actual_rules_string = new_actual_rules_string + rule.to_r
		} 
		new_expected_rules = "alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"101; rev:4; classtype:trojan-activity; priority:10; content:\"%u0074%u0065%u0073%u0074\"; uriconte"\
			+"nt:\"uri content\"; )"
			
		assert_equal(new_expected_rules,new_actual_rules_string,"Permutator did not generate expected unicodeEncode rules.")
	end
	def test_permutation_uuencode_multiple_content_fields
		permutator = SnortRulePermutator.new("analysisEngine/permutatorUnittest.rules")
		case_insensitive_rules = permutator.case_insensitize_rules(permutator.rules_orig)
		new_actual_rules = permutator.encode_rules(case_insensitive_rules,100, "uuencode")
		new_actual_rules_string = ""
		new_actual_rules.each { |rule| 
			new_actual_rules_string = new_actual_rules_string + rule.to_r
		} 
		
		new_expected_rules = "alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"100; rev:4; classtype:trojan-activity; priority:10; content:\"content1\"; uriconte"\
			+"nt:\"test\"; content:\"conte|nt2\"; content:\"8V]N=&5N=#,`\"; content:\"content4\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"101; rev:4; classtype:trojan-activity; priority:10; content:\"content1\"; uriconte"\
			+"nt:\"test\"; content:\"conte|nt2\"; content:\"8V]N=&5N=#,`\"; content:\"content4\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"102; rev:4; classtype:trojan-activity; priority:10; content:\"content1\"; uriconte"\
			+"nt:\"test\"; content:\"conte|nt2\"; content:\"8V]N=&5N=#,`\"; content:\"8V]N=&5N=#0`\"; "\
			+")"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"103; rev:4; classtype:trojan-activity; priority:10; content:\"8V]N=&5N=\#$`\"; uric"\
			+"ontent:\"test\"; content:\"conte|nt2\"; content:\"content3\"; content:\"content4\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"104; rev:4; classtype:trojan-activity; priority:10; content:\"8V]N=&5N=\#$`\"; uric"\
			+"ontent:\"test\"; content:\"conte|nt2\"; content:\"content3\"; content:\"8V]N=&5N=#0`\"; "\
			+")"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"105; rev:4; classtype:trojan-activity; priority:10; content:\"8V]N=&5N=\#$`\"; uric"\
			+"ontent:\"test\"; content:\"conte|nt2\"; content:\"8V]N=&5N=#,`\"; content:\"content4\"; "\
			+")"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule1 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000001\"; sid:"\
			+"106; rev:4; classtype:trojan-activity; priority:10; content:\"8V]N=&5N=\#$`\"; uric"\
			+"ontent:\"test\"; content:\"conte|nt2\"; content:\"8V]N=&5N=#,`\"; content:\"8V]N=&5N=#0"\
			+"`\"; )"\
			+"alert tcp !$HOME_NET !80:443 -> $EXTERNAL_NET $HTTP_PORTS (msg:\"rule3 msg"\
			+" - Generated by SnortRulePermutator based on SID - Generated by SnortRulePermutator based on SID 1000003\"; sid:"\
			+"107; rev:4; classtype:trojan-activity; priority:10; content:\"8V]N=&5N=\#$`\"; uric"\
			+"ontent:\"test\"; )"
			
		assert_equal(new_expected_rules,new_actual_rules_string,"Permutator did not generate expected rules.")
	end

end

#comment the next two lines out to enable running this unit test by executing
#ruby analysisEngine/SnortRulePermutator.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRulePermutatorTest)