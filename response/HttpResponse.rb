#!/usr/bin/env ruby

# Class HttpRequest simply wraps a http request object and allows for an xml representation
# Note that the xml representation that is being passed between queuer and visitor is 
# wrapped into a httpResponses tag
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require "rexml/text"
require "base64"

class HttpResponse
	attr_accessor :uri, :code, :body, :code_encoded, :headers, :headers_encoded, :encoded_content_types
	
	#initializer that requires the uri, return code and body
	def initialize(uri, code, body, headers)
		
	
		@uri = uri
		@uri_encoded = REXML::Text.normalize(@uri)

		@code = code
		@code_encoded = REXML::Text.normalize(@code.to_s)
		
		@headers = Hash.new
		headers.keys.each do | header_key |
			@headers[header_key.downcase] = headers[header_key]
		end
		
		@headers_encoded = Hash.new
		@headers.keys.each do |header_key|
			header_encoded_key = REXML::Text.normalize(header_key).downcase
			header_encoded_value = REXML::Text.normalize(@headers[header_key].to_s)
			@headers_encoded[header_encoded_key]=header_encoded_value
		end
		
		body = "" if body == nil
		@body = body
		@body_encoded = nil
		
	end
	
	#default to string representation
	def to_s
		@body_encoded = Base64.encode64(REXML::Text.normalize(@body)) if(@body_encoded==nil)

		encoded_header_str = ""
		@headers_encoded.keys.each do |header_encoded_key|
			header_encoded_value = @headers_encoded[header_encoded_key]
			encoded_header_str << ("<header name=\""+header_encoded_key.to_s+"\">"+header_encoded_value.to_s+"</header>\n")
		end
	
		"<httpResponse>\n<uri>" + @uri_encoded + "</uri>\n<code>" + @code_encoded.to_s\
			+ "</code>\n<headers>"+encoded_header_str+"</headers>\n"\
			+ "<body>" + @body_encoded + "</body>\n</httpResponse>\n" 
	end
	
	def header_str
		header_str = ""
		@headers.keys.each do |header_key|
			header_value = @headers[header_key]
			header_str << ("<header name=\""+header_key.to_s+"\">"+header_value.to_s+"</header>\n")
		end
		"<headers>"+header_str+"</headers>\n"
	end
	
	def match_str
		header_str = ""
		@headers.keys.each do |header_key|
			header_value = @headers[header_key]
			header_str << ("<header name=\""+header_key.to_s+"\">"+header_value.to_s+"</header>\n")
		end
	
		"<httpResponse>\n<uri>" + @uri + "</uri>\n<code>" + @code.to_s\
			+ "</code>\n<headers>"+header_str+"</headers>\n"\
			+ "<body>" + @body + "</body>\n</httpResponse>\n" 
	end
end

require 'test/unit/testcase'

# simple unit test for the HttpRequest class
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

class HttpResponseTest < Test::Unit::TestCase
	def test_to_s
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("test>",200,"&body",headers)
		assert_equal("<httpResponse>\n<uri>test&gt;</uri>\n<code>200</code>\n"\
			+ "<headers><header name=\"content-type\">text/html</header>\n"\
			+ "<header name=\"compre&gt;ssion\">gzip&amp;somethingElse</header>\n</headers>\n"\
			+ "<body>JmFtcDtib2R5\n</body>\n</httpResponse>\n",res.to_s,"to_s not as expected.")
	end
	
	def test_match_str
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("test>",200,"&body",headers)
		assert_equal("<httpResponse>\n<uri>test></uri>\n<code>200</code>\n"\
			+ "<headers><header name=\"content-type\">text/html</header>\n"\
			+ "<header name=\"compre>ssion\">gzip&somethingElse</header>\n</headers>\n"\
			+ "<body>&body</body>\n</httpResponse>\n",res.match_str,"to_s not as expected.")
	end
	
	def test_error_to_s
		res = HttpResponse.new("test>","500 error","&body", Hash.new)
		assert_equal("<httpResponse>\n<uri>test&gt;</uri>\n<code>500 error</code>\n<headers></headers>\n"\
			+ "<body>JmFtcDtib2R5\n</body>\n</httpResponse>\n",res.to_s,"to_s not as expected.")
	end
	
	def test_header_str
		headers = Hash["Content-Type"=>"text/html","compre>ssion"=>"gzip&somethingElse"]
		res = HttpResponse.new("test>",200,"&body",headers)
		
		expected_header_str = "<headers><header name=\"content-type\">text/html</header>\n"\
			+ "<header name=\"compre>ssion\">gzip&somethingElse</header>\n</headers>\n"
			
		assert_equal(expected_header_str, res.header_str, "header string doesnt match.")
	end
	
	def test_to_s_empty_headers
		headers = Hash.new
		res = HttpResponse.new("test>",200,"&body",headers)
		assert_equal("<httpResponse>\n<uri>test&gt;</uri>\n<code>200</code>\n<headers></headers>\n"\
			+ "<body>JmFtcDtib2R5\n</body>\n</httpResponse>\n",res.to_s,"to_s not as expected.")
	end
	
	def test_to_s_binary_body
		headers = Hash["content-type"=>"jpg"]
		res = HttpResponse.new("test>",200,"test",headers)
		assert_equal("<httpResponse>\n<uri>test&gt;</uri>\n<code>200</code>\n"\
			+"<headers><header name=\"content-type\">jpg</header>\n</headers>\n"\
			+ "<body>dGVzdA==\n</body>\n</httpResponse>\n",res.to_s,"to_s not as expected.")
	end
end

#comment the next two lines out to enable running this unit test by executing
#ruby response/HttpResponse.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(HttpResponseTest)
