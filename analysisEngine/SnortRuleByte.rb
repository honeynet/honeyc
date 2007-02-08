#!/usr/bin/env ruby

# object representation of a snort rule content.
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php
class SnortRuleByte
	attr_accessor :bytes_to_convert, :operator_not_modifier, :operator, :value, :offset, :relative, :endian, :string_lit, :number_type, :order_no

	def initialize
		@operator_not_modifer = false
		@number_type = "dec"
	end
	
	def to_s
		not_modifier = "!" if @operator_not_modifier
		
		"byte_test["+ @order_no.to_s + "]: " + @bytes_to_convert.to_s + ", " + not_modifier.to_s + @operator.to_s + ", "\
			+ @value.to_s + ", " + @offset.to_s + ", " + @relative.to_s + ", "\
			+ @endian.to_s + ", " + @number_type.to_s + ", " + @string_lit.to_s

	end
	
	def to_r
		not_mod = "!" if operator_not_modifier
		byte_test = "byte_test: "
		byte_test = byte_test + bytes_to_convert.to_s if bytes_to_convert
		byte_test = byte_test + "," + not_mod.to_s + operator.to_s if operator
		byte_test = byte_test + "," + value.to_s if value
		byte_test = byte_test + "," + offset.to_s if offset
		byte_test = byte_test + "," + relative.to_s if relative
		byte_test = byte_test + "," + endian.to_s if endian
		byte_test = byte_test + "," + string_lit.to_s if string_lit
		byte_test = byte_test + "," + number_type.to_s if number_type
		byte_test = byte_test + "; "
	end
	
	def get_focus_bytes(content, last_match_pos)
		if(relative!=nil)
			if(content.length>=offset+last_match_pos+bytes_to_convert)
				sub_str = content[offset+last_match_pos..offset+last_match_pos+bytes_to_convert]
			else
				sub_str = ""
			end
		else
			sub_str = content[offset..offset+bytes_to_convert]
		end
		
		if(sub_str == nil || sub_str.length==0)
			return -1
		end
		
		focus_bytes = 0
		number_bytes = bytes_to_convert
		sub_str.each_byte { |c|
			focus_bytes = focus_bytes + (c * (1<<((number_bytes-1)*8)))
			number_bytes = number_bytes-1
		}
		return focus_bytes
	end
	
	#todo - relative doesnt work since this class doesnt know the last match
	#little endian - not implemented
	def test(content, last_match_pos)
		success = false
		focus_bytes = get_focus_bytes(content, last_match_pos)
		
		if(focus_bytes!=-1)
			value_conv = value.hex if(number_type.index("hex")) 
			value_conv = value.oct if(number_type.index("oct"))
			value_conv = value.to_i if(number_type.index("dec"))
			
			case operator
				when "<"
					success = true if focus_bytes < value_conv
				when ">"
					success = true if focus_bytes > value_conv
				when "="
					success = true if (focus_bytes == value_conv)
				when "!"
					success = true if focus_bytes == !value_conv
				when "^"
					success = true if focus_bytes ^ value_conv == value_conv
				when "&"
					success = true if focus_bytes & value_conv == value_conv
				when "|"
					success = true if focus_bytes | value_conv == value_conv
				else
			end
		end
		
		success = !success if operator_not_modifier
		
		return success
	end
	
	def eql?(object)
		return self.to_s == object.to_s
	end
	
	def ==(object)
		return self.to_s == object.to_s
	end
end


require 'test/unit/testcase'

class SnortRuleByteTest < Test::Unit::TestCase
	def test_get_focus_bytes
		snort_rule_byte = SnortRuleByte.new
		snort_rule_byte.bytes_to_convert=2
		snort_rule_byte.offset=3
		actual_value = snort_rule_byte.get_focus_bytes("123he",0)
		expected_value = 104*256 + 101
		assert_equal(expected_value,actual_value,"get_focus_bytes returned incorrect value")
	end
	
	def test_content_match_hex
		snort_rule_byte = SnortRuleByte.new
		snort_rule_byte.bytes_to_convert=3
		snort_rule_byte.operator_not_modifier=false
		snort_rule_byte.operator="="
		snort_rule_byte.value="68656C" #byte 104 101 108, representing hel
		snort_rule_byte.offset=3
		snort_rule_byte.number_type="hex"
		assert(snort_rule_byte.test("123hel",0),"byte test failed")
	end

	def test_content_match_hex_relative
		snort_rule_byte = SnortRuleByte.new
		snort_rule_byte.bytes_to_convert=3
		snort_rule_byte.operator_not_modifier=false
		snort_rule_byte.operator="="
		snort_rule_byte.value="68656C" #byte 104 101 108, representing hel
		snort_rule_byte.offset=3
		snort_rule_byte.relative="relative"
		snort_rule_byte.number_type="hex"
		assert(snort_rule_byte.test("abcde123hel",5),"byte test failed")
	end
	
	def test_content_nomatch_hex_relative
		snort_rule_byte = SnortRuleByte.new
		snort_rule_byte.bytes_to_convert=3
		snort_rule_byte.operator_not_modifier=false
		snort_rule_byte.operator="="
		snort_rule_byte.value="68656C" #byte 104 101 108, representing hel
		snort_rule_byte.offset=3
		snort_rule_byte.relative="relative"
		snort_rule_byte.number_type="hex"
		assert(!snort_rule_byte.test("abcde123hel",6),"byte test succeeded on incorrect relative offset")
	end
	
	def test_content_match_dec
		snort_rule_byte = SnortRuleByte.new
		snort_rule_byte.bytes_to_convert=2
		snort_rule_byte.operator_not_modifier=false
		snort_rule_byte.operator="="
		snort_rule_byte.value=(104*256 + 101).to_s #byte 104 101 representing he
		snort_rule_byte.offset=3
		snort_rule_byte.number_type="dec"
		assert(snort_rule_byte.test("123he",0),"byte test failed")
	end

	def test_content_no_match_dec
		snort_rule_byte = SnortRuleByte.new
		snort_rule_byte.bytes_to_convert=2
		snort_rule_byte.operator_not_modifier=false
		snort_rule_byte.operator="="
		snort_rule_byte.value=(104*256 + 102).to_s #byte 104 101 representing he
		snort_rule_byte.offset=3
		snort_rule_byte.number_type="dec"
		assert(!snort_rule_byte.test("123he",0),"byte test failed")
	end
	
	def test_to_r
		snort_rule_byte = SnortRuleByte.new
		snort_rule_byte.bytes_to_convert=2
		snort_rule_byte.operator_not_modifier=false
		snort_rule_byte.operator="="
		snort_rule_byte.value=(104*256 + 102).to_s #byte 104 101 representing he
		snort_rule_byte.offset=3
		snort_rule_byte.number_type="dec"
		
		expected_str = "byte_test: 2,=,26726,3,dec; "
		assert_equal(expected_str,snort_rule_byte.to_r, "to r not correct.")
	end
end

#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRuleByteTest)
