# a grammar file to be input into racc to generate our snort rule parser
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

class SnortRuleParser

		
	token ACTION PROTOCOL ANY IP NOT DIRECTION INTEGER STRING VARIABLE LPAREN RPAREN
		MSG REFERENCE VALUE CONTENT URICONTENT ASSIGNMENT SEMICOLON NOCASE REV SID
		CLASSTYPE CLASSTYPE_VALUE PRIORITY DEPTH OFFSET WITHIN RAWBYTES DISTANCE 
		ISDATAAT RELATIVE PCRE COMMA BYTETEST OPERATOR ENDIAN NUMBERTYPE LITSTRING
		FLOW FLOW_VALUE FLOWBITS FLOWBITS_KEYWORD HEADERCONTENT
	
	rule
		target: ACTION PROTOCOL src_ip src_ports direction dst_ip dst_ports LPAREN statement_list RPAREN {
			@snort_rule.action = val[0]
			@snort_rule.protocol = val[1]
			}
		
		src_ip: NOT IP { @snort_rule.src_ip = val[0] + val[1] }
			| IP { @snort_rule.src_ip = val[0]}
			| NOT VARIABLE { @snort_rule.src_ip = val[0] + val[1] }
			| VARIABLE { @snort_rule.src_ip = val[0] }
			| ANY { @snort_rule.src_ip = val[0] }

		#currently only supports ranges; not comma separated ports
		src_ports: NOT INTEGER ASSIGNMENT INTEGER 	{ @snort_rule.src_ports_not = true  
								  @snort_rule.src_ports = val[1].to_i..val[3].to_i }
			| INTEGER ASSIGNMENT INTEGER	{ @snort_rule.src_ports = val[0].to_i..val[2].to_i }
			| NOT INTEGER ASSIGNMENT	{ @snort_rule.src_ports_not = true
						  @snort_rule.src_ports = val[1].to_i..65535 }
			| INTEGER ASSIGNMENT	{ @snort_rule.src_ports = val[0].to_i..65535 }
			| NOT ASSIGNMENT INTEGER	{ @snort_rule.src_ports_not = true
						  @snort_rule.src_ports = 0..val[2].to_i }
			| ASSIGNMENT INTEGER 	{ @snort_rule.src_ports = 0..val[0].to_i }
			| NOT INTEGER	{ @snort_rule.src_ports_not = true
					  @snort_rule.src_ports = val[1].to_i..val[1].to_i }
			| INTEGER	{ @snort_rule.src_ports = val[0].to_i..val[0].to_i }
			| NOT ANY	{ @snort_rule.src_ports_not = true
					  @snort_rule.src_ports = 0..65535 }
			| ANY	{ @snort_rule.src_ports_not = false
				  @snort_rule.src_ports = 0..65535 }	
			| NOT VARIABLE	{ @snort_rule.src_ports_not = true
					  @snort_rule.src_ports = val[1] }
			| VARIABLE	{ @snort_rule.src_ports = val[0] }	

		direction: DIRECTION {
			@snort_rule.direction = val[0] }
			
		dst_ip: NOT IP { @snort_rule.dst_ip = val[0] + val[1] }
			| IP { @snort_rule.dst_ip = val[0]}
			| NOT VARIABLE { @snort_rule.dst_ip = val[0] + val[1] }
			| VARIABLE { @snort_rule.dst_ip = val[0] }
			| ANY { @snort_rule.dst_ip = val[0] }

		dst_ports: NOT INTEGER ASSIGNMENT INTEGER 	{ @snort_rule.dst_ports_not = true  
								  @snort_rule.dst_ports = val[1].to_i..val[3].to_i }
			| INTEGER ASSIGNMENT INTEGER	{ @snort_rule.dst_ports = val[0].to_i..val[2].to_i }
			| NOT INTEGER ASSIGNMENT	{ @snort_rule.dst_ports_not = true
						 	  @snort_rule.dst_ports = val[1].to_i..65535 }
			| INTEGER ASSIGNMENT	{ @snort_rule.dst_ports = val[0].to_i..65535 }
			| NOT ASSIGNMENT INTEGER	{ @snort_rule.dst_ports_not = true
						  	  @snort_rule.dst_ports = 0..val[2].to_i }
			| ASSIGNMENT INTEGER 	{ @snort_rule.dst_ports = 0..val[0].to_i }
			| NOT INTEGER	{ @snort_rule.dst_ports_not = true
					  @snort_rule.dst_ports = val[1].to_i..val[1].to_i }
			| INTEGER	{ @snort_rule.dst_ports = val[0].to_i..val[0].to_i }
			| NOT ANY	{ @snort_rule.dst_ports_not = true
					  @snort_rule.dst_ports = 0..65535 }
			| ANY	{ @snort_rule.dst_ports_not = false
				  @snort_rule.dst_ports = 0..65535 }	
			| NOT VARIABLE	{ @snort_rule.dst_ports_not = true
					  @snort_rule.dst_ports = val[1] }
			| VARIABLE	{ @snort_rule.dst_ports = val[0] }
					  
		statement_list: statement SEMICOLON
			| statement_list statement_list
		
		statement: msg_assignment
			| reference_assignment
			| sid_assignment
			| rev_assignment
			| class_type_assignment
			| priority_assignment
			| content_assignment
			| uri_content_assignment 
			| header_content_assignment 
			| nocase
			| depth_assignment
			| raw_bytes
			| offset_assignment
			| distance_assignment
			| within_assignment
			| isdataat_assignment
			| pcre_assignment
			| byte_test_assignment
			| flow_assignment
			| flow_bit_assignment
			
		
		msg_assignment: MSG ASSIGNMENT STRING {
			@snort_rule.msg = val[2] }
			
		reference_assignment: REFERENCE ASSIGNMENT VALUE {
			@snort_rule.references.push(val[2]) }
			
		sid_assignment: SID ASSIGNMENT INTEGER {
			@snort_rule.sid = val[2].to_i }
			
		rev_assignment: REV ASSIGNMENT INTEGER {
			@snort_rule.rev = val[2].to_i }

		class_type_assignment: CLASSTYPE ASSIGNMENT CLASSTYPE_VALUE {
			@snort_rule.class_type = val[2] }
		
		content_assignment: CONTENT ASSIGNMENT NOT STRING { 
			@last_call = "content"
			@content = SnortRuleContent.new
			@content.order_no = @order_no
			@snort_rule.max_order_no = @order_no
			@order_no = @order_no + 1
			@snort_rule.contents.push(@content)
			@content.not_modifier = true
			@content.unescaped_string = unescape(val[3]) }
			| CONTENT ASSIGNMENT STRING { 
			@last_call = "content"
			@content = SnortRuleContent.new
			@content.order_no = @order_no
			@snort_rule.max_order_no = @order_no
			@order_no = @order_no + 1
			@snort_rule.contents.push(@content)
			@content.unescaped_string = unescape(val[2]) }
		
		priority_assignment: PRIORITY ASSIGNMENT INTEGER {
			@snort_rule.priority = val[2].to_i }
			
		nocase: NOCASE { 
			if @last_call == "content"
				@content.nocase = true
			elsif @last_call == "uri_content"
				@uri_content.nocase = true
			elsif @last_call == "header_content"
				@header_content.nocase = true
			end }
			
		raw_bytes: RAWBYTES { 
			if @last_call == "content"
				@content.raw_bytes = true
			elsif @last_call == "uri_content"
				@uri_content.raw_bytes = true
			elsif @last_call == "header_content"
				@header_content.raw_bytes = true
			end }

		depth_assignment: DEPTH ASSIGNMENT INTEGER {
			if @last_call == "content"
				@content.depth = val[2].to_i
			elsif @last_call == "uri_content"
				@uri_content.depth = val[2].to_i
			elsif @last_call == "header_content"
				@header_content.depth = val[2].to_i
			end }
			
		within_assignment: WITHIN ASSIGNMENT INTEGER {
			if @last_call == "content"
				@content.within = val[2].to_i
			elsif @last_call == "uri_content"
				@uri_content.within = val[2].to_i
			elsif @last_call == "header_content"
				@header_content.within = val[2].to_i
			end }
			
		offset_assignment: OFFSET ASSIGNMENT INTEGER {
			if @last_call == "content"
				@content.offset = val[2].to_i
			elsif @last_call == "uri_content"
				@uri_content.offset = val[2].to_i
			elsif @last_call == "header_content"
				@header_content.offset = val[2].to_i
			end }
			
		distance_assignment: DISTANCE ASSIGNMENT INTEGER {
			if @last_call == "content"
				@content.distance = val[2].to_i
			elsif @last_call == "uri_content"
				@uri_content.distance = val[2].to_i
			elsif @last_call == "header_content"
				@header_content.distance = val[2].to_i
			end }
		
		isdataat_assignment: ISDATAAT ASSIGNMENT INTEGER COMMA RELATIVE {
			@uri_content.isdataat = val[2] + val[3] + val[4] }
			| ISDATAAT ASSIGNMENT INTEGER {
			@uri_content.isdataat = val[2] }
			
		uri_content_assignment: URICONTENT ASSIGNMENT NOT STRING { 
			@last_call = "uri_content"
			@uri_content = SnortRuleUriContent.new
			@uri_content.order_no = @order_no
			@snort_rule.max_order_no = @order_no
			@order_no = @order_no + 1
			@snort_rule.uri_contents.push(@uri_content)
			@uri_content.not_modifier = true
			@uri_content.unescaped_string = unescape(val[3]) }
			| URICONTENT ASSIGNMENT STRING { 
			@last_call = "uri_content"
			@uri_content = SnortRuleUriContent.new
			@uri_content.order_no = @order_no
			@snort_rule.max_order_no = @order_no
			@order_no = @order_no + 1
			@snort_rule.uri_contents.push(@uri_content)
			@uri_content.unescaped_string = unescape(val[2]) }
			
		header_content_assignment: HEADERCONTENT ASSIGNMENT NOT STRING { 
			@last_call = "header_content"
			@header_content = SnortRuleHeaderContent.new
			@header_content.order_no = @order_no
			@snort_rule.max_order_no = @order_no
			@order_no = @order_no + 1
			@snort_rule.header_contents.push(@header_content)
			@header_content.not_modifier = true
			@header_content.unescaped_string = unescape(val[3]) }
			| HEADERCONTENT ASSIGNMENT STRING { 
			@last_call = "header_content"
			@header_content = SnortRuleHeaderContent.new
			@header_content.order_no = @order_no
			@snort_rule.max_order_no = @order_no
			@order_no = @order_no + 1
			@snort_rule.header_contents.push(@header_content)
			@header_content.unescaped_string = unescape(val[2]) }

		pcre_assignment: PCRE ASSIGNMENT NOT STRING {
			pcre = SnortRulePcre.new
			pcre.order_no = @order_no
			@snort_rule.max_order_no = @order_no
			@order_no = @order_no + 1
			pcre.not_modifier = true
			last_slash = val[3].rindex("/")
			pcre.regex = val[3][0..last_slash]
			pcre.modifiers = val[3][last_slash+1..-1]
			@snort_rule.pcres.push(pcre) }
			| PCRE ASSIGNMENT STRING {
			pcre = SnortRulePcre.new
			pcre.order_no = @order_no
			@snort_rule.max_order_no = @order_no
			@order_no = @order_no + 1
			last_slash = val[2].rindex("/")
			pcre.regex = val[2][0..last_slash]
			pcre.modifiers = val[2][last_slash+1..-1]
			@snort_rule.pcres.push(pcre) }
			
		byte_test_assignment: BYTETEST ASSIGNMENT INTEGER COMMA NOT OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA RELATIVE COMMA ENDIAN COMMA LITSTRING COMMA NUMBERTYPE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator_not_modifier = true
				snort_rule_byte_test.operator = val[5]
				snort_rule_byte_test.value = val[7].to_i
				snort_rule_byte_test.offset = val[9].to_i
				snort_rule_byte_test.relative = val[11]
				snort_rule_byte_test.endian = val[13]
				snort_rule_byte_test.number_type = val[15]
				snort_rule_byte_test.string_lit = val[17]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA RELATIVE COMMA ENDIAN COMMA LITSTRING COMMA NUMBERTYPE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator_not_modifier = true
				snort_rule_byte_test.operator = val[4]
				snort_rule_byte_test.value = val[6].to_i
				snort_rule_byte_test.offset = val[8].to_i
				snort_rule_byte_test.relative = val[10]
				snort_rule_byte_test.endian = val[12]
				snort_rule_byte_test.number_type = val[14]
				snort_rule_byte_test.string_lit = val[16]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA NOT OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA ENDIAN COMMA LITSTRING COMMA NUMBERTYPE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator_not_modifier = true
				snort_rule_byte_test.operator = val[5]
				snort_rule_byte_test.value = val[7].to_i
				snort_rule_byte_test.offset = val[9].to_i
				snort_rule_byte_test.endian = val[11]
				snort_rule_byte_test.number_type = val[13]
				snort_rule_byte_test.string_lit = val[15]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA ENDIAN COMMA LITSTRING COMMA NUMBERTYPE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator = val[4]
				snort_rule_byte_test.value = val[6].to_i
				snort_rule_byte_test.offset = val[8].to_i
				snort_rule_byte_test.endian = val[10]
				snort_rule_byte_test.number_type = val[12]
				snort_rule_byte_test.string_lit = val[14]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA NOT OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA RELATIVE COMMA LITSTRING COMMA NUMBERTYPE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator_not_modifier = true
				snort_rule_byte_test.operator = val[5]
				snort_rule_byte_test.value = val[7].to_i
				snort_rule_byte_test.offset = val[9].to_i
				snort_rule_byte_test.relative = val[11]
				snort_rule_byte_test.number_type = val[13]
				snort_rule_byte_test.string_lit = val[15]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA RELATIVE COMMA LITSTRING COMMA NUMBERTYPE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator = val[4]
				snort_rule_byte_test.value = val[6].to_i
				snort_rule_byte_test.offset = val[8].to_i
				snort_rule_byte_test.relative = val[10]
				snort_rule_byte_test.number_type = val[12]
				snort_rule_byte_test.string_lit = val[14]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA NOT OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA RELATIVE COMMA ENDIAN {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator_not_modifier = true
				snort_rule_byte_test.operator = val[5]
				snort_rule_byte_test.value = val[7].to_i
				snort_rule_byte_test.offset = val[9].to_i
				snort_rule_byte_test.relative = val[11]
				snort_rule_byte_test.endian = val[13]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA RELATIVE COMMA ENDIAN {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator = val[4]
				snort_rule_byte_test.value = val[6].to_i
				snort_rule_byte_test.offset = val[8].to_i
				snort_rule_byte_test.relative = val[10]
				snort_rule_byte_test.endian = val[12]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA NOT OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA RELATIVE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator_not_modifier = true
				snort_rule_byte_test.operator = val[5]
				snort_rule_byte_test.value = val[7].to_i
				snort_rule_byte_test.offset = val[9].to_i
				snort_rule_byte_test.relative = val[11]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA RELATIVE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator = val[4]
				snort_rule_byte_test.value = val[6].to_i
				snort_rule_byte_test.offset = val[8].to_i
				snort_rule_byte_test.relative = val[10]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA NOT OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA LITSTRING COMMA NUMBERTYPE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator_not_modifier = true
				snort_rule_byte_test.operator = val[5]
				snort_rule_byte_test.value = val[7].to_i
				snort_rule_byte_test.offset = val[9].to_i
				snort_rule_byte_test.number_type = val[11]
				snort_rule_byte_test.string_lit = val[13]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA LITSTRING COMMA NUMBERTYPE {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator = val[4]
				snort_rule_byte_test.value = val[8].to_i
				snort_rule_byte_test.offset = val[10].to_i
				snort_rule_byte_test.number_type = val[12]
				snort_rule_byte_test.string_lit = val[14]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA NOT OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA ENDIAN {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator_not_modifier = true
				snort_rule_byte_test.operator = val[5]
				snort_rule_byte_test.value = val[7].to_i
				snort_rule_byte_test.offset = val[9].to_i
				snort_rule_byte_test.endian = val[11]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA OPERATOR 
			COMMA INTEGER COMMA INTEGER COMMA ENDIAN {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator = val[4]
				snort_rule_byte_test.value = val[6].to_i
				snort_rule_byte_test.offset = val[8].to_i
				snort_rule_byte_test.endian = val[10]
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA NOT OPERATOR 
			COMMA INTEGER COMMA INTEGER {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator_not_modifier = true
				snort_rule_byte_test.operator = val[5]
				snort_rule_byte_test.value = val[7].to_i
				snort_rule_byte_test.offset = val[9].to_i
				}
			| BYTETEST ASSIGNMENT INTEGER COMMA OPERATOR 
			COMMA INTEGER COMMA INTEGER {
				snort_rule_byte_test = SnortRuleByte.new
				snort_rule_byte_test.order_no = @order_no
				@snort_rule.max_order_no = @order_no
				@order_no = @order_no + 1
				@snort_rule.byte_test = snort_rule_byte_test
				snort_rule_byte_test.bytes_to_convert = val[2].to_i
				snort_rule_byte_test.operator = val[4]
				snort_rule_byte_test.value = val[6].to_i
				snort_rule_byte_test.offset = val[8].to_i
				}
				
		flow_assignment: FLOW ASSIGNMENT FLOW_VALUE {
			@snort_rule.flow = val[2] }

		flow_bit_assignment: FLOWBITS ASSIGNMENT FLOWBITS_KEYWORD COMMA VALUE {
			flow_bit = SnortRuleFlowBit.new
			flow_bit.key_word = val[2]
			flow_bit.value = val[4]
			@snort_rule.flow_bits.push(flow_bit) }
			| FLOWBITS ASSIGNMENT FLOWBITS_KEYWORD {
			flow_bit = SnortRuleFlowBit.new
			flow_bit.key_word = val[2]
			@snort_rule.flow_bits.push(flow_bit) }
end

---- header
#!/usr/bin/env ruby

# a simple parser for generating snort rule objects. this is an automatically
# generated class by racc using the SnortRuleParser.y file.
#
# There are the following limitations: 
#	-non payload match is limited to flow and flowbits
#	-only alert action is supported
#	-ftpbounce is not supported
#	-byte_jump is not supported
#	-tag is not supported
#	-from_begining is not supported
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'analysisEngine/SnortRuleLexer'
require 'analysisEngine/SnortRule'
require 'analysisEngine/SnortRuleContent'
require 'analysisEngine/SnortRuleUriContent'
require 'analysisEngine/SnortRuleHeaderContent'
require 'analysisEngine/SnortRuleByte'
require 'analysisEngine/SnortRuleFlowBit'
---- inner
	def parse(rule_str)
		#lex it
		@q = SnortRuleLexer.tokenize(rule_str)
		@snort_rule = SnortRule.new
		@order_no = 0
		do_parse
		return @snort_rule
	end
	
	def next_token
		@q.shift
	end

	def parse_rules(rules_location)
		rules = Array.new
		IO.foreach(rules_location) {|rule_string|
			begin
				if(rule_string.length > 1 && rule_string.index("#")!=0)
					snort_rule = parse(rule_string)
					if (snort_rule.relevant?)
					    snort_rule.check
					    rules.push(snort_rule) 	
				    	end
				end
			rescue StandardError => error
				STDERR.puts "Unable to parse rule " + rule_string + ": "
				STDERR.puts error
			end
		}
		return rules
	end

	def unescape(str)
		#replace \\ with \
		#replace \" with "
		#replace \: with :
		#replace \; with ;
		while(str.sub(/\\\"/, "\"")!=str)
			str.sub!("\\\"","\"")
		end
		while(str.sub(/\\:/, ":")!=str)
			str.sub!("\\:",":")
		end
		while(str.sub(/\\;/, ";")!=str)
			str.sub!("\\;",";")
		end	
		while(str.sub(/\\\\/, "\\")!=str)
			str.sub!(/\\\\/,"\\")
		end
		return str
	end
	
---- footer
#!/usr/bin/env ruby

# Class SnortRuleParserTest is a simple unit test of SnortRuleParser parse_rules method
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'
require 'analysisEngine/SnortRule'
require 'analysisEngine/SnortRulePcre'
require 'analysisEngine/SnortRuleByte'
require 'analysisEngine/SnortRuleUriContent'
require 'analysisEngine/SnortRuleHeaderContent'
require 'analysisEngine/SnortRuleContent'

class SnortRuleParserTest < Test::Unit::TestCase

	#test constructor and getters
	def test_initialize_tc16
		parser = SnortRuleParser.new 
		rules = parser.parse_rules("analysisEngine/unittest.rules")
		assert_equal(2,rules.length,"length not as expected")
		
		expected_references = Array["url,http://someref1.com","url,http://someotherref2.com"]
		expected_content1 = SnortRuleContent.new
		expected_content1.not_modifier = true
		expected_content1.nocase = true
		expected_content1.unescaped_string = "a \"string"
		expected_content1.depth = 3
		expected_content1.within = 4
		expected_content1.order_no = 0
		expected_content2 = SnortRuleContent.new
		expected_content2.unescaped_string = "another string"
		expected_content2.order_no = 4
		expected_contents = Array[expected_content1,expected_content2]
		expected_header_content1 = SnortRuleHeaderContent.new
		expected_header_content1.unescaped_string = "text/html"
		expected_header_content1.order_no = 1
		expected_header_contents = Array[expected_header_content1]
		expected_uri_content1 = SnortRuleUriContent.new
		expected_uri_content1.unescaped_string = "uri content string"
		expected_uri_content1.raw_bytes = true
		expected_uri_content1.distance = 10
		expected_uri_content1.offset = 3
		expected_uri_content1.order_no = 2
		expected_uri_content2 = SnortRuleUriContent.new
		expected_uri_content2.unescaped_string ="another uri content string"
		expected_uri_content2.isdataat = "50,relative"
		expected_uri_content2.nocase = true
		expected_uri_content2.order_no = 3
		expected_uri_contents = Array[expected_uri_content1,expected_uri_content2]
		expected_pcre1 = SnortRulePcre.new
		expected_pcre1.not_modifier = true
		expected_pcre1.modifiers = "i"
		expected_pcre1.regex = "/rule1pcre/"
		expected_pcre1.order_no = 5
		expected_pcre2 = SnortRulePcre.new
		expected_pcre2.not_modifier = false
		expected_pcre2.modifiers = "i"
		expected_pcre2.regex = "/rule1pcre2/"
		expected_pcre2.order_no = 7
		expected_pcres = Array[expected_pcre1,expected_pcre2]
		expected_byte_test = SnortRuleByte.new
		expected_byte_test.bytes_to_convert = 4
		expected_byte_test.operator = ">"
		expected_byte_test.value = 1000
		expected_byte_test.offset = 20
		expected_byte_test.relative = "relative"
		expected_byte_test.order_no = 6
		rule1 = rules[0]
		expected_flow_bits = Array.new
		flow_bit1 = SnortRuleFlowBit.new
		flow_bit1.key_word = "noalert"
		expected_flow_bits.push(flow_bit1)
		flow_bit2 = SnortRuleFlowBit.new
		flow_bit2.key_word = "set"
		flow_bit2.value = "test"
		expected_flow_bits.push(flow_bit2)
		
		assert_equal(7,rule1.max_order_no,"rule1: max order no not as expected.")
		assert_equal("alert",rule1.action,"rule1: alert not as expected.")
		assert_equal("tcp",rule1.protocol,"rule1: protocol not as expected.")
		assert_equal("!$HOME_NET",rule1.src_ip,"rule1: src_ip not as expected.")
		assert_equal(true,rule1.src_ports_not,"rule1: src_ports_not not as expected.")
		assert_equal(80..443,rule1.src_ports,"rule1: src_ports not as expected.")
		assert_equal("->",rule1.direction,"rule1: direction not as expected.")
		assert_equal("$EXTERNAL_NET",rule1.dst_ip,"rule1: dst_ip not as expected.")
		assert_equal(false,rule1.dst_ports_not,"rule1: dst_ports_not not as expected.")
		assert_equal("$HTTP_PORTS",rule1.dst_ports,"rule1: dst_ports not as expected.")
		
		assert_equal("rule1 msg",rule1.msg,"rule1: msg not as expected.")
		assert_equal(expected_references,rule1.references,"rule1: references not as expected.")
		assert_equal(1000001,rule1.sid,"rule1: sid not as expected.")
		assert_equal(4,rule1.rev,"rule1: rev not as expected.")
		assert_equal("trojan-activity",rule1.class_type,"rule1: classtype not as expected.")
		assert_equal(10,rule1.priority,"rule1: priority not as expected.")
		assert_equal(expected_contents,rule1.contents,"rule1: contents not as expected.")
		assert_equal(expected_header_contents,rule1.header_contents,"rule1: headercontents  not as expected.")
		assert_equal(expected_uri_contents,rule1.uri_contents,"rule1: uricontents  not as expected.")
		assert_equal("to_server,established",rule1.flow,"rule1: flow not as expected.")
		assert_equal(expected_pcres,rule1.pcres,"rule1: pcres not as expected.")
		assert_equal(expected_byte_test,rule1.byte_test,"rule1: byte_test not as expected.")
		assert_equal(expected_flow_bits,rule1.flow_bits,"rule1: flow bits not as expected.")

	end
	
	#commented out since we dont deliver these rules with honeyC. still a good test case though.
	#def test_initialize
	#	parser = SnortRuleParser.new
	#	rules = parser.parse_rules("analysisEngine/bleeding-malware.rules")
	#	puts "loaded " + rules.length.to_s + " rules."
	#end
end

#comment the next two lines out to enable running this unit test by executing
# ruby analysisEngine/SnortRuleParser.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRuleParserTest)

