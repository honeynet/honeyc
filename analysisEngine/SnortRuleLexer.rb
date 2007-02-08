#!/usr/bin/env ruby

# a simple lexter for snort rules. (only accounts for tokens other than non-payload rule tokens)
# returns an array of Ruby Symbol, value to be used by the racc parser. The last entry in the array is false, $end
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php
class SnortRuleLexer
	def SnortRuleLexer.tokenize(rule_str)
		tokens = []
		until rule_str.empty?
			case rule_str #order is important
				when /\A#.*/
					#ignore comments
				when /\A"\/[^\"]*?\[.*?\".*?\][^\"]*?\/.*?[^\\]"/ #match everything in quotes shortest match. but make sure last quote is not escaped
					tokens.push [:STRING, $&[1..-2]]
				when /\A".*?[^\\]"/ #match everything in quotes shortest match. but make sure last quote is not escaped
					tokens.push [:STRING, $&[1..-2]]
				when /\A[ ]|\A\n|\A\t/
					#ignore white space
				when /\A\$[a-zA-Z_]+/
					tokens.push [:VARIABLE, $&]
				when /\Aflowbits/i
					tokens.push [:FLOWBITS, $&]
				when /\Arelative/i
					tokens.push [:RELATIVE, $&]
				when /\A\(/
					tokens.push [:LPAREN, $&]
				when /\Aany|\AANY/
					tokens.push [:ANY, $&]
				when /\A\)/
					tokens.push [:RPAREN, $&]
				when /\Aalert|\Alog|\Apass|\Adrop|\Areject|\Asdrop/i
					tokens.push [:ACTION, $&]
				when /\Atcp|\Audp|\Aip|\Aicmp/i
					tokens.push [:PROTOCOL, $&]
				when /\Ahex|\Aoct|\Adec/i
					tokens.push [:NUMBERTYPE, $&]
				when /\Abig|\Alittle/i
					tokens.push [:ENDIAN, $&]
				when /(\Ato_client|\Ato_server|\Afrom_client|\Afrom_server)(,established|,stateless)?(,no_stream|,only_stream)?|(\Aestablished|\Astateless)(,to_client|,to_server|,from_client|,from_server)?(,no_stream|,only_stream)?/i
					tokens.push [:FLOW_VALUE, $&]
				when /(\Aisset|\Aset|\Aunset|\Anoalert|\Aisnotset|\Atoggle)/i
					tokens.push [:FLOWBITS_KEYWORD, $&]
				when /\A:/
					tokens.push [:ASSIGNMENT, $&]
				when /\A->|\A<-|\A<>/
					tokens.push [:DIRECTION, $&]
				when /\A,/
					tokens.push [:COMMA, $&]	
				when /\A;/
					tokens.push [:SEMICOLON, $&]	
				when /\Anocase/i
					tokens.push [:NOCASE, $&]	
				when /\Arelative/i
					tokens.push [:RELATIVE, $&]
				when /\Astring/i
					tokens.push [:LITSTRING, $&]
				when /\Aalign/i
					tokens.push [:ALIGN, $&]
				when /\Amsg/i
					tokens.push [:MSG, $&]
				when /\Areference/i
					tokens.push [:REFERENCE, $&]
				when /\Aflow/i
					tokens.push [:FLOW, $&]
				when /\Asid/i
					tokens.push [:SID, $&]
				when /\Arev/i
					tokens.push [:REV, $&]
				when /\Aclasstype/i
					tokens.push [:CLASSTYPE, $&]
				when /\Apcre/i
					tokens.push [:PCRE, $&]
				when /\Awithin/i
					tokens.push [:WITHIN, $&]
				when /\Adistance/i
					tokens.push [:DISTANCE, $&]
				when /\Apriority/i
					tokens.push [:PRIORITY, $&]
				when /\Adepth/i
					tokens.push [:DEPTH, $&]
				when /\Aoffset/i
					tokens.push [:OFFSET, $&]
				when /\Aisdataat/i
					tokens.push [:ISDATAAT, $&]
				when /\Abyte_test/i
					tokens.push [:BYTETEST, $&]
				when /\Arawbytes/i
					tokens.push [:RAWBYTES, $&]
				when /\Aheadercontent/i
					tokens.push [:HEADERCONTENT, $&]
				when /\Auricontent/i
					tokens.push [:URICONTENT, $&]
				when /\Aattempted-admin|\Aattempted-user|\Ashellcode-detect|\Asuccessful-admin|\Asuccessful-user|\Atrojan-activity|\Aunsuccessful-user|\Aweb-application-attack|\Aattempted-dos|\Aattempted-recon|\Abad-unknown|\Adenial-of-service|\Amisc-attack|\Anon-standard-protocol|\Arpc-portmap-decode|\Asuccessful-dos|\Asuccessful-recon-largescale|\Asuccessful-recon-limited|\Asuspicious-filename-detect|\Asuspicious-login|\Asystem-call-detect|\Aunusual-client-port-connection|\Aweb-application-activity|\Aicmp-event|\Amisc-activity|\Apolicy-violation|\Anetwork-scan|\Anot-suspicious|\Aprotocol-command-decode|\Astring-detect|\Aunknown/i
					tokens.push [:CLASSTYPE_VALUE, $&]
				when /\Acontent/i
					tokens.push [:CONTENT, $&]
				when /\A(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/
					tokens.push [:IP, $&]
				when /\A0x[0-9]+|\A-[0-9]+|\A[0-9]+/
					tokens.push [:INTEGER, $&]
				when /\A>=|\A<=/
					tokens.push [:OPERATOR, $&]
				when /\A[&\-<>=^]/
					tokens.push [:OPERATOR, $&]
				when /\A!/
					tokens.push [:NOT, $&]
				#alphanumeric chars with special characters to create url
				when /\A(\\;|[a-zA-Z0-9\#_,:\/.\?\-=%&])+/ 
					tokens.push [:VALUE, $&]
		
			end
			#puts "last match: " + Regexp.last_match.to_s
			#puts "rule_str: " + rule_str.to_s
			rule_str = Regexp.last_match.post_match.strip
		end
		tokens.push [false, '$end']
		#puts tokens
		return tokens
	end
end

#!/usr/bin/env ruby

# Class SnortRuleLexerTest is a simple unit test of SnortRuleLexer
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'

class SnortRuleLexerTest < Test::Unit::TestCase
	def test_tokenize_full_rule
		expected_tokens = []
		expected_tokens.push [:ACTION, "alert"]
		expected_tokens.push [:PROTOCOL, "tcp"]
		expected_tokens.push [:VARIABLE, "$HOME_NET"]
		expected_tokens.push [:ANY, "any"]
		expected_tokens.push [:DIRECTION, "->"]
		expected_tokens.push [:VARIABLE, "$EXTERNAL_NET"]
		expected_tokens.push [:VARIABLE, "$HTTP_PORTS"]
		expected_tokens.push [:LPAREN, "("]
		expected_tokens.push [:MSG, "msg"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:STRING, "BLEEDING-EDGE Malware Incredisearch.com Spyware Ping"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:FLOW, "flow"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:FLOW_VALUE, "to_server,established"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:HEADERCONTENT, "headercontent"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:NOT, "!"]
		expected_tokens.push [:STRING, "text/html"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:URICONTENT, "uricontent"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:STRING, "/ping.asp?something&test"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:NOCASE, "nocase"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:CONTENT, "content"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:STRING, "incred|3a|isearch \\\"com"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:DEPTH, "depth"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:INTEGER, "300"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:NOCASE, "nocase"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:BYTETEST, "byte_test"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:INTEGER, "4"]
		expected_tokens.push [:COMMA, ","]
		expected_tokens.push [:OPERATOR, ">="]
		expected_tokens.push [:COMMA, ","]
		expected_tokens.push [:INTEGER, "0x1000"]
		expected_tokens.push [:COMMA, ","]
		expected_tokens.push [:INTEGER, "20"]
		expected_tokens.push [:COMMA, ","]
		expected_tokens.push [:RELATIVE, "relative"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:PCRE, "pcre"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:STRING, "/a reg[^\"']e[^'\"]{256}x/i"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:CLASSTYPE, "classtype"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:CLASSTYPE_VALUE, "trojan-activity"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:SID, "sid"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:INTEGER, "2001793"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:REV, "rev"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:INTEGER, "4"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:REFERENCE, "reference"]
		expected_tokens.push [:ASSIGNMENT, ":"]
		expected_tokens.push [:VALUE, "url,http://www.some-url.com/path/?somevar=val%20go&otherval"]
		expected_tokens.push [:SEMICOLON, ";"]
		expected_tokens.push [:RPAREN, ")"]
		expected_tokens.push [false, '$end']
		
		rule = "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS"\
			+ "(msg: \"BLEEDING-EDGE Malware Incredisearch.com Spyware Ping\";"\
			+ " flow: to_server,established; headercontent:!\"text/html\"; uricontent:\"/ping.asp?something&test\"; nocase;"\
			+ " content:\"incred|3a|isearch \\\"com\"; depth:300; nocase; byte_test: 4,>=,0x1000,20,relative;"\
			+ " pcre: \"/a reg[^\"']e[^'\"]{256}x/i\"; classtype:"\
			+ " trojan-activity; sid: 2001793; rev:4; reference:url,http://www.some-url.com/path/?somevar=val%20go&otherval; ) # some comment"
		actual_tokens = SnortRuleLexer.tokenize(rule)
		
		assert_equal(expected_tokens, actual_tokens, "tokens not as expected.")
		
	end
	def test_tokenize_comment
		expected_tokens = []
		expected_tokens.push [false, '$end']
		
		rule = "#alert tcp any any <> any any (msg: \"rule3 msg\"; reference:"\
			+ "url,http://rule3.com; sid:1000003; flow: to_client,established; rev:1; uricontent:\"uricontentA\";"\
			+ "nocase; content:\"contentA\"; classtype:trojan-activity; content:\"contentB\"; nocase; pcre:\"/rule3pcre/\"; )"
		actual_tokens = SnortRuleLexer.tokenize(rule)
		
		assert_equal(expected_tokens, actual_tokens, "tokens not as expected.")
		
	end
end

#comment the next two lines out to enable running this unit test by executing
# ruby analysisEngine/SnortRuleLexer.rb
#require 'test/unit/ui/console/testrunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRuleLexerTest)