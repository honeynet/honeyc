#!/usr/bin/env ruby

# object representation of a snort rule flow bit
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php
class SnortRuleFlowBit
	attr_accessor :key_word, :value
	
	#map of flow bit values and server address
	@@flow_bit_map = Hash.new

	def initialize

	end
	
	def SnortRuleFlowBit.flow_bit_map
		return @@flow_bit_map
	end
	
	def SnortRuleFlowBit.reset_flow_bit_map
		@@flow_bit_map = Hash.new
	end
	
	#depending on the keyword, it adds or checks the flow bit
	#if flow bit is set and a check is performed, this function returns true
	#if flow bit is not set, flow bit will be set and true is returned
	def eval(server)
		if(key_word.eql?("set"))
			@@flow_bit_map[value] = Array.new if @@flow_bit_map[value] == nil
			@@flow_bit_map[value].push(server)
		elsif(key_word.eql?("isset"))
			return false if @@flow_bit_map[value] == nil
			return false if !@@flow_bit_map[value].include?(server)
		end
		return true
	end
	
	def to_s
		"flowbit: " + @key_word.to_s + ", " + @value.to_s
	end
	
	def to_r
		flowbits = "flowbits: " + @key_word.to_s
		flowbits = flowbits + "," + @value.to_s if value != nil
		flowbits = flowbits + "; "
	end
	
	def eql?(object)
		return self.to_s == object.to_s
	end
	
	def ==(object)
		return self.to_s == object.to_s
	end
end


require 'test/unit/testcase'

class SnortRuleFlowBitTest < Test::Unit::TestCase
	def test_eval_set
		flow_bit = SnortRuleFlowBit.new
		flow_bit.key_word = "set"
		flow_bit.value = "test"
		returnVal = flow_bit.eval("test_server")
		
		assert(returnVal, "eval did not eval to true")
		assert(SnortRuleFlowBit.flow_bit_map["test"].include?("test_server"),"set eval didnt set map value")
		
		SnortRuleFlowBit.reset_flow_bit_map
	end
	
	def test_eval_isset_after_set
		flow_bit1 = SnortRuleFlowBit.new
		flow_bit1.key_word = "set"
		flow_bit1.value = "test"
		flow_bit1.eval("test_server")
		
		flow_bit2 = SnortRuleFlowBit.new
		flow_bit2.key_word = "isset"
		flow_bit2.value = "test"
		returnVal = flow_bit2.eval("test_server")

		assert(returnVal, "eval did not eval to true on isset altough flowbit was set")
		
		SnortRuleFlowBit.reset_flow_bit_map
	end

	def test_eval_isset_default
		flow_bit = SnortRuleFlowBit.new
		flow_bit.key_word = "isset"
		flow_bit.value = "test"
		returnVal = flow_bit.eval("test_server")
		
		assert(!returnVal,"isset eval did not return false on missing flow bit")
		
		SnortRuleFlowBit.reset_flow_bit_map

	end

	def test_eval_noalert
		flow_bit = SnortRuleFlowBit.new
		flow_bit.key_word = "noalert"
		returnVal = flow_bit.eval("test_server")
		
		assert(returnVal, "noalert didnt return true on eval")
		
		SnortRuleFlowBit.reset_flow_bit_map
	end

	def test_eval_set_different_servers
		flow_bit = SnortRuleFlowBit.new
		flow_bit.key_word = "set"
		flow_bit.value = "test"
		returnVal1 = flow_bit.eval("test_server1")
		returnVal2 = flow_bit.eval("test_server2")
		
		
		assert(returnVal1, "eval did not eval to true")
		assert(returnVal2, "eval did not eval to true")
		assert(SnortRuleFlowBit.flow_bit_map["test"].include?("test_server1"),"set eval didnt set map value")
		assert(SnortRuleFlowBit.flow_bit_map["test"].include?("test_server2"),"set eval didnt set map value")
		
		SnortRuleFlowBit.reset_flow_bit_map
	end

	def test_eval_isset_different_servers
		flow_bit1 = SnortRuleFlowBit.new
		flow_bit1.key_word = "set"
		flow_bit1.value = "test"
		flow_bit1.eval("test_server1")
		
		flow_bit2 = SnortRuleFlowBit.new
		flow_bit2.key_word = "isset"
		flow_bit2.value = "test"
		returnVal = flow_bit2.eval("test_server2")

		assert(!returnVal, "eval did not eval to false on isset altough flowbit was not set")
		
		SnortRuleFlowBit.reset_flow_bit_map
	end

	def test_to_r
		snort_rule_flow_bit = SnortRuleFlowBit.new
		snort_rule_flow_bit.key_word = "set"
		snort_rule_flow_bit.value="test"
		
		expected_str = "flowbits: set,test; "
		assert_equal(expected_str,snort_rule_flow_bit.to_r, "to r not correct.")
	end
end

#require 'test/unit/ui/console/testrunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRuleFlowBitTest)
