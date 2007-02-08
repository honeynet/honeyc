#!/usr/bin/env ruby

# object representation of a snort rule
#
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php
require "uri"

require "response/HttpResponse"
require "analysisEngine/SnortRuleContent"
require "analysisEngine/SnortRuleHeaderContent"
require "analysisEngine/SnortRuleUriContent"
require "analysisEngine/SnortRulePcre"
require "analysisEngine/SnortRuleByte"
require "analysisEngine/SnortRuleFlowBit"

class SnortRule
	attr_accessor :action, :protocol, :src_ip, :src_ports_not, :src_ports, :direction, :dst_ip, :dst_ports_not, :dst_ports,\
		:msg, :references, :sid, :rev, :class_type, :class_type_long, :priority, :contents, :header_contents, :uri_contents,\
		:pcres, :byte_test, :flow, :flow_bits, :max_order_no
		
	def initialize()
		@flow_bits = Array.new
		@contents = Array.new
		@uri_contents = Array.new
		@header_contents = Array.new
		@references = Array.new
		@flow_bits = Array.new
		@pcres = Array.new
		@src_ports_not = false
		@dst_ports_not = false
		
		@http_ports = [80,8080,443]
	end

	def deep_clone
		copy = self.clone
		copy.flow_bits = flow_bits.collect { |flow_bit| flow_bit.clone } if flow_bits
		copy.contents = contents.collect { |content| content.clone } if contents
		copy.uri_contents = uri_contents.collect { |uri_content| uri_content.clone } if uri_contents
		copy.header_contents = header_contents.collect { |header_content| header_content.clone } if header_contents
		copy.references = references.collect { |reference| reference.clone } if references
		copy.pcres = pcres.collect { |pcre| pcre.clone} if pcres
		copy.byte_test = byte_test.clone if byte_test
		copy
	end
	
	#setter of classtype that also sets the classtypeLong and priority
	#only trojan-activity, attempted-dos, attempted-recon are currently supported
	def class_type= (class_type)
		@class_type = class_type
		#TODO - needs to be extended
		if(class_type=="attempted-admin")
			@class_type_long = "Attempted Administrator Privilege Gain"
			@priority = 1
		elsif(class_type=="policy-violation")
			@class_type_long = "Policy Violation"
			@priority = 3
		elsif(class_type=="attempted-user")
			@class_type_long = "Attempted User Privilege Gain"
			@priority = 1
		elsif(class_type=="shellcode-detect")
			@class_type_long = "Executable code was detected"
			@priority = 1
		elsif(class_type=="successful-admin")
			@class_type_long = "Successful Administrator Privilege Gain"
			@priority = 1
		elsif(class_type=="successful-user")
			@class_type_long = "Successful User Privilege Gain"
			@priority = 1
		elsif(class_type=="trojan-activity")
			@class_type_long = "A Network Trojan was detected"
			@priority = 1
		elsif(class_type=="unsuccessful-user")
			@class_type_long = "Unsuccessful User Privilege Gain"
			@priority = 1
		elsif(class_type=="web-application-attack")
			@class_type_long = "Web Application Attack"
			@priority = 1
		elsif(class_type=="bad-unknown")
			@class_type_long = "Potentially Bad Traffic"
			@priority = 2
		elsif(class_type=="denial-of-service")
			@class_type_long = "Detection of a Denial of Service Attack"
			@priority = 2
		elsif(class_type=="misc-attack")
			@class_type_long = "Misc Attack"
			@priority = 2
		elsif(class_type=="non-standard-protocol")
			@class_type_long = "Detection of a non-standard protocol or event"
			@priority = 2
		elsif(class_type=="rpc-portmap-decode")
			@class_type_long = "Decode of an RPC Query"
			@priority = 2
		elsif(class_type=="successful-dos")
			@class_type_long = "Denial of Service"
			@priority = 2
		elsif(class_type=="successful-recon-largescale")
			@class_type_long = "Large Scale Information Leak"
			@priority = 2
		elsif(class_type=="successful-recon-limited")
			@class_type_long = "Information Leak"
			@priority = 2
		elsif(class_type=="suspicious-filename-detect")
			@class_type_long = "A suspicious filename was detected"
			@priority = 2
		elsif(class_type=="suspicious-login")
			@class_type_long = "An attempted login using a suspicious username was detected"
			@priority = 2
		elsif(class_type=="system-call-detect")
			@class_type_long = "A system call was detected"
			@priority = 2
		elsif(class_type=="unusual-client-port-connection")
			@class_type_long = "A client was using an unusual port"
			@priority = 2
		elsif(class_type=="web-application-activity")
			@class_type_long = "access to a potentially vulnerable web application"
			@priority = 2
		elsif(class_type=="icmp-event")
			@class_type_long = "Generic ICMP event"
			@priority = 3
		elsif(class_type=="misc-activity")
			@class_type_long = "Misc activity"
			@priority = 3
		elsif(class_type=="network-scan")
			@class_type_long = "Detection of a Network Scan"
			@priority = 3
		elsif(class_type=="not-suspicious")
			@class_type_long = "Not Suspicious Traffic"
			@priority = 3
		elsif(class_type=="protocol-command-decode")
			@class_type_long = "Generic Protocol Command Decode"
			@priority = 3
		elsif(class_type=="string-detect")
			@class_type_long = "A suspicious string was detected"
			@priority = 3
		elsif(class_type=="unknown")
			@class_type_long = "Unknown Traffic"
			@priority = 3
		elsif(class_type=="attempted-dos")
			@class_type_long = "Attempted Denial of Service"
			@priority = 2
		elsif(class_type=="attempted-recon")
			@class_type_long = "Attempted Information Leak"
			@priority = 2
		end
	end
	
	#just do a sanity check on the underlying options. this fuction is being
	#called as soon as the rule is parsed
	def check
		last_match = 0
		(0..@max_order_no).each do |order_no|
			content_str = "a test string"
			@uri_contents.each {|uri_content|
				if uri_content.order_no == order_no
					#STDERR.puts "uri matched" if(uri_content.match(content_str, last_match))
					#STDERR.puts "uri mis matched" if(!uri_content.match(content_str, last_match))
					uri_content.match(content_str, last_match)
				end
			}
			
			@header_contents.each {|header_content|
				if header_content.order_no == order_no
					#STDERR.puts "header matched" if(header_content.match(content_str, last_match))
					#STDERR.puts "header mis matched" if(!header_content.match(content_str, last_match))
					header_content.match(content_str, last_match)
				end
			}
			
			@contents.each {|content|
				if content.order_no == order_no
					#STDERR.puts "content matched" if(content.match(content_str, last_match))
					#STDERR.puts "content mis matched" if(!content.match(content_str, last_match))
					content.match(content_str, last_match)
				end
	
			}
			
			@pcres.each {|pcre|
				if pcre.order_no == order_no
					#STDERR.puts "pcre matched" if(pcre.match(content_str))
					#STDERR.puts "pcre mis matched" if(!pcre.match(content_str))
					pcre.match(content_str, last_match)
				end
	
			}
			
			#STDERR.puts "bytes matched" if(@byte_test.test(content_str, last_match)) if @byte_test != nil
			#STDERR.puts "byte mis matched" if(!@byte_test.test(content_str, last_match)) if @byte_test != nil
			if @byte_test != nil && @byte_test.order_no == order_no
				@byte_test.test(content_str, last_match) if @byte_test != nil
			end
		end
	end
	
	def match(content_obj)
		#STDERR.puts self.to_s
		last_match = 0
		last_match_uri = 0
		last_match_header = 0
		content_str = ""
		match = true
		(0..@max_order_no).each do |order_no|
			
			uri_str = ""
			body_str = ""
			header_str = ""
			if(content_obj.class.to_s=="HttpResponse")
				content_str = content_obj.match_str
				uri_str = content_obj.uri.to_s
				body_str = content_obj.body.to_s
				header_str = content_obj.header_str
			else #just for unit tests
				content_str = content_obj.to_s
				uri_str = content_str
				body_str = content_str
				header_str = content_str
			end
			@uri_contents.each {|uri_content|
				if uri_content.order_no == order_no
					#STDERR.puts "uri matched" if(uri_content.match(uri_str, last_match_uri))
					#STDERR.puts "uri mis matched" if(!uri_content.match(uri_str, last_match_uri))
					last_match_uri = uri_content.match(uri_str, last_match_uri)
					return false if(!last_match_uri)
				end
			}
			
			@header_contents.each {|header_content|
				if header_content.order_no == order_no
					#STDERR.puts "header matched" if(header_content.match(header_str, last_match_header))
					#STDERR.puts "header mis matched" if(!header_content.match(header_str, last_match_header))
					last_match_header = header_content.match(header_str, last_match_header)
					return false if(!last_match_header)
				end
			}
			
			@contents.each {|content|
				if content.order_no == order_no
					#STDERR.puts "content matched" if(content.match(content_str,last_match))
					#STDERR.puts "content mis matched" if(!content.match(content_st,last_matchr))
					last_match = content.match(content_str,last_match)
					return false if(!last_match)
				end
	
			}
			
			@pcres.each {|pcre|
				if pcre.order_no == order_no
					if(pcre.modifiers.index("U")==nil && pcre.modifiers.index("H")==nil)
						#STDERR.puts "pcre matched" if(pcre.match(content_str,last_match))
						#STDERR.puts "pcre mis matched" if(!pcre.match(content_str,last_match))
						last_match = pcre.match(content_str,last_match)
						return false if(!last_match)
					else
						if(pcre.modifiers.index("H")==nil)
							#must have U
							#STDERR.puts "URI pcre matched" if(pcre.match(uri_str,last_match_uri))
							#STDERR.puts "URI pcre mis matched" if(!pcre.match(uri_str,last_match_uri))
							last_match_uri = pcre.match(uri_str,last_match_uri)
							return false if(!last_match_uri)
						else
							#must have H
							#STDERR.puts "Header pcre matched" if(pcre.match(header_str,last_match_header))
							#STDERR.puts "Header pcre mis matched" if(!pcre.match(header_str,last_match_header))
							last_match_header = pcre.match(header_str,last_match_header)
							return false if(!last_match_header)
						end
					end
					
				end
	
			}
			
			#STDERR.puts "bytes matched" if(@byte_test.test(content_str, last_match)) if @byte_test != nil
			#STDERR.puts "byte mis matched" if(!@byte_test.test(content_str, last_match)) if @byte_test != nil
			if @byte_test != nil && @byte_test.order_no == order_no
				return false if(!@byte_test.test(body_str, last_match)) if @byte_test != nil
			end
		end

		if(match)
			@flow_bits.each {|flow_bit|
				server = ""
				if(content_obj.class.to_s=="HttpResponse")
					uri = content_obj.uri.to_s
					server = URI.parse(uri).host
				else #just for unit tests
					server = content_str
				end
				match = flow_bit.eval(server)
				return false if(!match)
			}
		end
		
		return match
	end
	
	def relevant?
		if(!(action.index("any") || action.index("alert")))
			return false
		end
		
		if(!(protocol.index("any") || protocol.index("tcp")))
			return false
		end
		
		if(flow == nil || flow.index("to_server") || flow.index("from_client"))
			if(dst_ports.class==Range && !(dst_ports.member?(80)))
				return false if !dst_ports_not 
			end
			if(dst_ports.class==String && !(dst_ports.index("any") || dst_ports.index("$HTTP_PORTS")))
				return false if !dst_ports_not 
			end
			if(!(dst_ip.index("any") || dst_ip.index("$EXTERNAL_NET")))
				return false
			end
			if(src_ports.class==String && !(src_ports.index("any")))
				return false if !src_ports_not 
			end
			if(!(src_ip.index("any") || src_ip.index("$HOME_NET") || src_ip.index("127.0.0.1") || src_ip.index("localhost")))
				return false
			end
		else
			if(src_ports.class==Range && !(src_ports.member?(80)))
				return false if !src_ports_not 
			end
			if(src_ports.class==String && !(src_ports.index("any") || src_ports.index("$HTTP_PORTS")))
				return false if !src_ports_not 
			end
			if(!(src_ip.index("any") || src_ip.index("$EXTERNAL_NET")))
				return false
			end
			if(dst_ports.class==String && !(dst_ports.index("any")))
				return false if !dst_ports_not 
			end

			if(!(dst_ip.index("any") || dst_ip.index("$HOME_NET") || dst_ip.index("127.0.0.1") || dst_ip.index("localhost")))
				return false
			end
		end
		
		return true
	end
	
	def to_s
		"Snort Rule \n"\
			+" [Action: " + @action.to_s + "; Protocol: " + @protocol.to_s + "; \n"\
			+ " SrcIP: " + src_ip.to_s + " SrcPorts: " + src_ports.to_s + " NegateSrcPorts: " + @src_ports_not.to_s + "; \n"\
			+ " Direction: " + direction.to_s + "\n"\
			+ " DstIP: " + dst_ip.to_s + " DstPorts: " + dst_ports.to_s + " NegateDstPorts: " + @dst_ports_not.to_s + "; \n"\
			+ " (\n"\
			+ " Msg:" +@msg.to_s+";\n"\
			+ " References["+@references.length.to_s+"]: " +@references.to_s+";\n"\
			+ " Sid:" +@sid.to_s+";\n"\
			+ " Rev:" +@rev.to_s+";\n"\
			+ " Classtype:" +@class_type.to_s+"," + @class_type_long.to_s + "," + @priority.to_s + ";\n"\
			+ " Contents["+@contents.length.to_s+"]: "+@contents.to_s+"; \n"\
			+ " Headercontents["+@header_contents.length.to_s+"]: "+@header_contents.to_s+ "; \n"\
			+ " Uricontents["+@uri_contents.length.to_s+"]: "+@uri_contents.to_s+ "; \n"\
			+ " PCRE["+@pcres.length.to_s+"]: "+@pcres.to_s + "; \n"\
			+ " byte_test: "+@byte_test.to_s+ "; \n"\
			+ " flowbits["+@flow_bits.length.to_s+"]: " + @flow_bits.to_s+ "; \n"\
			+ " flow: "+@flow.to_s+ "; \n"\
			+ ")]"
	end
	
	def to_r
		src_ports_str = ""
		if(src_ports.class == Range)
			if(src_ports.first==0 and src_ports.last==65535)
				src_ports_str = "any"
			else
				src_ports_str = src_ports.first.to_s + ":" + src_ports.last.to_s
			end
		else
			src_ports_str = src_ports.to_s
		end
		negate_src_ports = ""
		if(@src_ports_not.to_s == "true")
			negate_src_ports="!"
		end
		
		dst_ports_str = ""
		if(dst_ports.class == Range)
			if(dst_ports.first==0 and dst_ports.last==65535)
				dst_ports_str = "any"
			else
				dst_ports_str = dst_ports.first.to_s + ":" + dst_ports.last.to_s
			end
		else
			dst_ports_str = dst_ports.to_s
		end
		negate_dst_ports = ""
		if(@dst_ports_not.to_s == "true")
			negate_dst_ports="!"
		end

		msg_str = "msg:\"" + msg + "\"; " if(msg)
	
		references_str = ""
		@references.each { |reference| 
			references_str = references_str + "reference:"+reference.to_s+"; "
		}
		
		sid_str = "sid:"+sid.to_s+"; " if(sid)
		
		rev_str = "rev:"+rev.to_s+"; " if(rev)
		
		class_type_str = "classtype:" + class_type.to_s + "; " if(class_type)
		priority_str = "priority:" + priority.to_s + "; " if(class_type)
		
		match_str = ""
		(0..@max_order_no).each do |order_no|
			@uri_contents.each {|uri_content|
				match_str = match_str + uri_content.to_r if uri_content.order_no == order_no
			}
			@header_contents.each {|header_content|
				match_str = match_str + header_content.to_r if header_content.order_no == order_no
			}
			@contents.each {|content|
				match_str = match_str + content.to_r if content.order_no == order_no
			}
			@pcres.each {|pcre|
				match_str = match_str + pcre.to_r if pcre.order_no == order_no
			}
			match_str = match_str + byte_test.to_r if @byte_test != nil && @byte_test.order_no == order_no
		end
		
		flow_str = "flow: " + flow.to_s + "; " if flow                     
		flow_bits_str = ""
		@flow_bits.each { |flow_bit| 
			flow_bits_str = "flowbits: " + flow_bit.to_s + "; " if flow_bit
		}
		
		#:uri_contents, :pcre, :byte_test,\
		#:flow, :flow_bits, :max_order_no
		
		@action.to_s + " " + @protocol.to_s + " " + src_ip.to_s + " " + negate_src_ports + src_ports_str + " "\
		+ @direction.to_s + " " + dst_ip.to_s + " " + negate_dst_ports + dst_ports_str + " "\
		+ "(" + msg_str.to_s + references_str.to_s + sid_str.to_s + rev_str.to_s + class_type_str.to_s\
		+ priority_str.to_s + match_str.to_s + flow_str.to_s + flow_bits_str.to_s\
		+ ")"
	end
end

#!/usr/bin/env ruby

# Class SnortRuleTest is a simple unit test of SnortRule
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'

class SnortRuleTest < Test::Unit::TestCase
	#test constructor and getters
	def test_initialize
		
	end

	def test_deep_clone
		snort_rule1 = SnortRule.new
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.order_no = 0
		snort_rule_content.unescaped_string = "test content" #equals MyMatch123
		snort_rule_content.nocase = true
		snort_rule1.contents.push(snort_rule_content)
		
		snort_rule2 = snort_rule1.deep_clone
		snort_rule2.contents[0].unescaped_string = "some content"
		
		assert_not_equal(snort_rule2.contents[0].unescaped_string, snort_rule1.contents[0].unescaped_string, "Deep clone didnt work. Modifications to one rule affected clone.")
	end
	
	
	def test_relevant_false
		snort_rule = SnortRule.new
		snort_rule.action="alert"
		snort_rule.protocol="tcp"
		snort_rule.src_ip="$HOME_NET"
		snort_rule.src_ports_not=false
		snort_rule.src_ports="any"
		snort_rule.direction="->"
		snort_rule.dst_ip="$EXTERNAL_NET"
		snort_rule.dst_ports_not=false
		snort_rule.dst_ports=22..22
		snort_rule.flow="to_server,established"
		assert(!snort_rule.relevant?,"irrelevant snort rule relevant")
	end

	def test_relevant_true_variables_to_client
		#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any
		snort_rule = SnortRule.new
		snort_rule.action="alert"
		snort_rule.protocol="tcp"
		snort_rule.src_ip="$EXTERNAL_NET"
		snort_rule.src_ports_not=false
		snort_rule.src_ports="$HTTP_PORTS"
		snort_rule.direction="->"
		snort_rule.dst_ip="$HOME_NET"
		snort_rule.dst_ports_not=false
		snort_rule.dst_ports="any"
		snort_rule.flow="to_client,established"
		assert(snort_rule.relevant?,"snort rule not relevant")
		
	end

	def test_relevant_true_specifics_to_client
		#alert tcp $EXTERNAL_NET 80 -> $HOME_NET any
		snort_rule = SnortRule.new
		snort_rule.action="alert"
		snort_rule.protocol="tcp"
		snort_rule.src_ip="$EXTERNAL_NET"
		snort_rule.src_ports_not=false
		snort_rule.src_ports=80..80
		snort_rule.direction="->"
		snort_rule.dst_ip="$HOME_NET"
		snort_rule.dst_ports_not=false
		snort_rule.dst_ports="any"
		snort_rule.flow="to_client,established"
		assert(snort_rule.relevant?,"snort rule not relevant")
	end

	def test_relevant_true_wildcards_to_client
		#alert tcp any any -> any any
		snort_rule = SnortRule.new
		snort_rule.action="alert"
		snort_rule.protocol="tcp"
		snort_rule.src_ip="any"
		snort_rule.src_ports_not=false
		snort_rule.src_ports="any"
		snort_rule.direction="->"
		snort_rule.dst_ip="any"
		snort_rule.dst_ports_not=false
		snort_rule.dst_ports="any"
		snort_rule.flow="to_client,established"
		assert(snort_rule.relevant?,"snort rule not relevant")
	end
	
	def test_relevant_true_variables_to_server
		#alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
		snort_rule = SnortRule.new
		snort_rule.action="alert"
		snort_rule.protocol="tcp"
		snort_rule.src_ip="$HOME_NET"
		snort_rule.src_ports_not=false
		snort_rule.src_ports="any"
		snort_rule.direction="->"
		snort_rule.dst_ip="$EXTERNAL_NET"
		snort_rule.dst_ports_not=false
		snort_rule.dst_ports="$HTTP_PORTS"
		snort_rule.flow="to_server,established"
		assert(snort_rule.relevant?,"snort rule not relevant")
	end

	def test_relevant_true_specifics_to_server
		#alert tcp $HOME_NET any -> $EXTERNAL_NET 80
		snort_rule = SnortRule.new
		snort_rule.action="alert"
		snort_rule.protocol="tcp"
		snort_rule.src_ip="$HOME_NET"
		snort_rule.src_ports_not=false
		snort_rule.src_ports="any"
		snort_rule.direction="->"
		snort_rule.dst_ip="$EXTERNAL_NET"
		snort_rule.dst_ports_not=false
		snort_rule.dst_ports=80..80
		snort_rule.flow="to_server,established"
		assert(snort_rule.relevant?,"snort rule not relevant")
	end

	def test_relevant_true_wildcards_to_server
		#alert tcp any any -> any any
		snort_rule = SnortRule.new
		snort_rule.action="alert"
		snort_rule.protocol="tcp"
		snort_rule.src_ip="any"
		snort_rule.src_ports_not=false
		snort_rule.src_ports="any"
		snort_rule.direction="->"
		snort_rule.dst_ip="any"
		snort_rule.dst_ports_not=false
		snort_rule.dst_ports="any"
		snort_rule.flow="to_server,established"
		assert(snort_rule.relevant?,"snort rule not relevant")
	end
	
	
	def test_match_all
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 4
		
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.order_no = 0
		snort_rule_content.unescaped_string = "test content" #equals MyMatch123
		snort_rule_content.nocase = true
		snort_rule.contents.push(snort_rule_content)
		
		snort_rule_header_content = SnortRuleHeaderContent.new
		snort_rule_header_content.order_no = 1
		snort_rule_header_content.unescaped_string = "PIECE"
		snort_rule_header_content.nocase = true
		snort_rule.header_contents.push(snort_rule_header_content)

		snort_rule_uri_content = SnortRuleUriContent.new
		snort_rule_uri_content.order_no = 2
		snort_rule_uri_content.unescaped_string = "M|79|Mat|63 68|123" #equals MyMatch123
		snort_rule_uri_content.nocase = false
		snort_rule.uri_contents.push(snort_rule_uri_content)
		
		pcre = SnortRulePcre.new
		pcre.order_no = 3
		pcre.not_modifier= false
		pcre.regex = "/test/"
		pcre.modifiers = ""
		snort_rule.pcres.push(pcre)
		
		snort_rule_byte = SnortRuleByte.new
		snort_rule_byte.order_no = 4
		snort_rule_byte.bytes_to_convert=2
		snort_rule_byte.operator_not_modifier=false
		snort_rule_byte.operator="="
		snort_rule_byte.value=(104*256 + 101).to_s #byte 104 101 representing he
		snort_rule_byte.offset=3
		snort_rule_byte.number_type="dec"
		snort_rule.byte_test = snort_rule_byte
		
		assert(snort_rule.match("thihes is a piece of test content: MyMatch123"),"match on test content failed")
	end
	
	def test_match_flow_bits
		#create two rules of which the one is dependent on the other via flow bits setting
		#expose to content that matches on first rule
		#expose to content that matches on second rule
		#both should match
		snort_rule1 = SnortRule.new
		snort_rule1.max_order_no = 1
		
		snort_rule_uri_content1 = SnortRuleUriContent.new
		snort_rule_uri_content1.order_no = 1
		snort_rule_uri_content1.unescaped_string = "honeyC" 
		snort_rule_uri_content1.nocase = false
		snort_rule1.uri_contents.push(snort_rule_uri_content1)
		
		snort_rule_flow_bit1 = SnortRuleFlowBit.new
		snort_rule_flow_bit1.key_word = "set"
		snort_rule_flow_bit1.value = "something"
		snort_rule1.flow_bits.push(snort_rule_flow_bit1)
			
		headers1 = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res1 = HttpResponse.new("http://some.honeyC.com",200,"&body",headers1)
		assert(snort_rule1.match(res1),"initial match on honeyC uri failed")
		
		snort_rule2 = SnortRule.new
		snort_rule2.max_order_no = 1
		
		snort_rule_content1 = SnortRuleUriContent.new
		snort_rule_content1.order_no = 1
		snort_rule_content1.unescaped_string = "body" 
		snort_rule_content1.nocase = false
		snort_rule2.contents.push(snort_rule_content1)
		
		snort_rule_flow_bit2 = SnortRuleFlowBit.new
		snort_rule_flow_bit2.key_word = "isset"
		snort_rule_flow_bit2.value = "something"
		snort_rule2.flow_bits.push(snort_rule_flow_bit2)
			
		headers2 = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res2 = HttpResponse.new("http://some.honeyC.com",200,"&body",headers2)
		assert(snort_rule2.match(res2),"follow on match in which flowbit is checked didnt fire.")
		
		SnortRuleFlowBit.reset_flow_bit_map
	end
	
	def test_no_match_flow_bits
		#like previous test, but now remove flowbit condition on first rule
		#since no flow bit was set, second rule should also not fire
		snort_rule1 = SnortRule.new
		snort_rule1.max_order_no = 1
		
		snort_rule_uri_content1 = SnortRuleUriContent.new
		snort_rule_uri_content1.order_no = 1
		snort_rule_uri_content1.unescaped_string = "honeyC" 
		snort_rule_uri_content1.nocase = false
		snort_rule1.uri_contents.push(snort_rule_uri_content1)
		
		headers1 = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res1 = HttpResponse.new("http://some.honeyC.com",200,"&body",headers1)
		assert(snort_rule1.match(res1),"initial match on honeyC uri failed")
		
		snort_rule2 = SnortRule.new
		snort_rule2.max_order_no = 1
		
		snort_rule_content1 = SnortRuleUriContent.new
		snort_rule_content1.order_no = 1
		snort_rule_content1.unescaped_string = "body" 
		snort_rule_content1.nocase = false
		snort_rule2.contents.push(snort_rule_content1)
		
		snort_rule_flow_bit2 = SnortRuleFlowBit.new
		snort_rule_flow_bit2.key_word = "isset"
		snort_rule_flow_bit2.value = "something"
		snort_rule2.flow_bits.push(snort_rule_flow_bit2)
			
		headers2 = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res2 = HttpResponse.new("http://some.honeyC.com",200,"&body",headers2)
		assert(!snort_rule2.match(res2),"follow on match in which flowbit incorrectly evaluates to true did fire.")
		
		SnortRuleFlowBit.reset_flow_bit_map
	end
	

	def test_match_header_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		snort_rule_header_content = SnortRuleHeaderContent.new
		snort_rule_header_content.order_no = 1
		snort_rule_header_content.unescaped_string = "name=\"content-type\">text/html<" 
		snort_rule_header_content.nocase = true
		snort_rule.header_contents.push(snort_rule_header_content)
		
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.honeyC.com",200,"&body",headers)
		assert(snort_rule.match(res),"match on text/html failed")
	end
	
	def test_no_match_header_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		snort_rule_header_content = SnortRuleHeaderContent.new
		snort_rule_header_content.order_no = 1
		snort_rule_header_content.unescaped_string = "text/html" 
		snort_rule_header_content.nocase = true
		snort_rule.header_contents.push(snort_rule_header_content)
		
		headers = Hash["Content-Type"=>"image/gif/","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.honeyC.com",200,"some text/html content",headers)
		assert(!snort_rule.match(res),"match on text/html failed")
	end
	
	def test_match_uri_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		snort_rule_uri_content = SnortRuleUriContent.new
		snort_rule_uri_content.order_no = 1
		snort_rule_uri_content.unescaped_string = "honeyC" 
		snort_rule_uri_content.nocase = false
		snort_rule.uri_contents.push(snort_rule_uri_content)
		
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.honeyC.com",200,"&body",headers)
		assert(snort_rule.match(res),"match on honeyC failed")
	end
	
	
	
	
	
	def test_match_pcre_header_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		pcre = SnortRulePcre.new
		pcre.order_no = 1
		pcre.not_modifier= false
		pcre.regex = "/honeyC/"
		pcre.modifiers = "H"
		snort_rule.pcres.push(pcre)
		
		headers = Hash["Content-Type"=>"honeyC","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.no.com",200,"&body",headers)
		assert(snort_rule.match(res),"pcre match on honeyC in header failed")
	end

	def test_match_pcre_header_without_modifier
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		pcre = SnortRulePcre.new
		pcre.order_no = 1
		pcre.not_modifier= false
		pcre.regex = "/honeyC/"
		pcre.modifiers = ""
		snort_rule.pcres.push(pcre)
		
		headers = Hash["Content-Type"=>"honeyC","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.com",200,"&body",headers)
		assert(snort_rule.match(res),"pcre match on honeyC failed")
	end
	
	def test_no_match_pcre_header_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		pcre = SnortRulePcre.new
		pcre.order_no = 1
		pcre.not_modifier= false
		pcre.regex = "/honeyC/"
		pcre.modifiers = "H"
		snort_rule.pcres.push(pcre)
		
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.honeyC.com",200,"something with honeyC",headers)
		assert(!snort_rule.match(res),"pcre match on honeyC failed")
	end
	
	
	
	
	
	
	
	def test_match_pcre_uri_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		pcre = SnortRulePcre.new
		pcre.order_no = 1
		pcre.not_modifier= false
		pcre.regex = "/honeyC/"
		pcre.modifiers = "U"
		snort_rule.pcres.push(pcre)
		
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.honeyC.com",200,"&body",headers)
		assert(snort_rule.match(res),"pcre match on honeyC failed")
	end

	def test_match_pcre_uri_without_modifier
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		pcre = SnortRulePcre.new
		pcre.order_no = 1
		pcre.not_modifier= false
		pcre.regex = "/honeyC/"
		pcre.modifiers = ""
		snort_rule.pcres.push(pcre)
		
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.honeyC.com",200,"&body",headers)
		assert(snort_rule.match(res),"pcre match on honeyC failed")
	end
	
	def test_no_match_pcre_uri_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		pcre = SnortRulePcre.new
		pcre.order_no = 1
		pcre.not_modifier= false
		pcre.regex = "/honeyC/"
		pcre.modifiers = "U"
		snort_rule.pcres.push(pcre)
		
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.no.com",200,"something with honeyC",headers)
		assert(!snort_rule.match(res),"pcre match on honeyC failed")
	end
	
	def test_no_match_uri_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		snort_rule_uri_content = SnortRuleUriContent.new
		snort_rule_uri_content.order_no = 1
		snort_rule_uri_content.unescaped_string = "honeyC" 
		snort_rule_uri_content.nocase = false
		snort_rule.uri_contents.push(snort_rule_uri_content)
		
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("nothing",200,"http://some.honeyC.com in the body",headers)
		assert(!snort_rule.match(res),"match on honeyC failed")
	end
	
	def test_match_bytetest_on_body_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		pcre = SnortRulePcre.new
		pcre.order_no = 1
		pcre.not_modifier= false
		pcre.regex = "/honeyC/"
		pcre.modifiers = "U"
		snort_rule.pcres.push(pcre)
		
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.no.com",200,"something with honeyC",headers)
		assert(!snort_rule.match(res),"pcre match on honeyC failed")
	end
	
	def test_no_match_bytetest_on_body_only
		snort_rule = SnortRule.new
		snort_rule.max_order_no = 1
		
		pcre = SnortRulePcre.new
		pcre.order_no = 1
		pcre.not_modifier= false
		pcre.regex = "/honeyC/"
		pcre.modifiers = "U"
		snort_rule.pcres.push(pcre)
		
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("http://some.no.com",200,"something with honeyC",headers)
		assert(!snort_rule.match(res),"pcre match on honeyC failed")
	end
	
	def test_to_r
		snort_rule = SnortRule.new
		snort_rule.action="alert"
		snort_rule.protocol="tcp"
		snort_rule.src_ip="$HOME_NET"
		snort_rule.src_ports_not=false
		snort_rule.src_ports="any"
		snort_rule.direction="->"
		snort_rule.dst_ip="$EXTERNAL_NET"
		snort_rule.dst_ports_not=false
		snort_rule.dst_ports="$HTTP_PORTS"
		snort_rule.msg="Test rule"
		snort_rule.class_type="attempted-admin"
		snort_rule.flow="to_server,established"		
		
		snort_rule.max_order_no = 3
		
		snort_rule_content = SnortRuleContent.new
		snort_rule_content.order_no = 0
		snort_rule_content.unescaped_string = "test content" 
		snort_rule_content.nocase = true
		snort_rule.contents.push(snort_rule_content)
		
		snort_rule_uri_content = SnortRuleUriContent.new
		snort_rule_uri_content.order_no = 1
		snort_rule_uri_content.unescaped_string = "M|79|Mat|63 68|123" #equals MyMatch123
		snort_rule_uri_content.nocase = false
		snort_rule.uri_contents.push(snort_rule_uri_content)
		
		pcre = SnortRulePcre.new
		pcre.order_no = 2
		pcre.not_modifier= false
		pcre.regex = "/test/"
		pcre.modifiers = ""
		snort_rule.pcres.push(pcre)
		
		snort_rule_byte = SnortRuleByte.new
		snort_rule_byte.order_no = 3
		snort_rule_byte.bytes_to_convert=2
		snort_rule_byte.operator_not_modifier=false
		snort_rule_byte.operator="="
		snort_rule_byte.value=(104*256 + 102).to_s #byte 104 101 representing he
		snort_rule_byte.offset=3
		snort_rule_byte.number_type="dec"
		snort_rule.byte_test = snort_rule_byte
		
		expected_str = "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS "\
			+ "(msg:\"Test rule\"; classtype:attempted-admin; priority:1; "\
			+ "content:\"test content\"; nocase; "\
			+ "uricontent:\"M|79|Mat|63 68|123\"; "\
			+ "pcre:\"/test/\"; "\
			+ "byte_test: 2,=,26726,3,dec; "\
			+ "flow: to_server,established; "\
			+ ")"
		assert_equal(expected_str,snort_rule.to_r,"to r not correct for snort rule.")
	end
end

#comment the next two lines out to enable running this unit test by executing
# ruby analysisEngine/SnortRule.rb
#require 'test/unit/ui/console/testrunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRuleTest)