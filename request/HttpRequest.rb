#!/usr/bin/env ruby

# Class HttpRequest simply wraps a http request object and allows for an xml representation
# Note that the xml representation that is being passed between queuer and visitor is 
# wrapped into a httpRequests tag
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require "rexml/text"

class HttpRequest
	attr_accessor :uri, :uri_xml_encoded_only, :follow_link
	
	#initializer that requires the uri object
	#uri should not be encoded
	def initialize(uri)
		@uri = clean(uri)
		@uri_xml_encoded_only = REXML::Text.normalize(@uri)
		
		
		@follow_link = true
	end
	
	def clean(uri)
		if(uri.length>6)
			#start after https://
			uri_pre = uri[0..6]
			uri = uri[7..-1]
			
			#remove new lines
			while(uri.sub(/\n/, '')!=uri)
				uri = uri.sub(/\n/, '')
			end

			#remove double slashes
			while(uri.sub(/\/\//, '/')!=uri)
				uri = uri.sub(/\/\//, '/')
			end

			#remove path traversal - replace /path/../ with /
			while(uri.sub(/\/[^\/]*\/\.\.\//, '/'))!=uri
				uri = uri.sub(/\/[^\/]*\/\.\.\//, '/')
			end
			
			#remove remaining path traversal - replace /../ with /
			while(uri.sub(/\/\.\.\//, '/'))!=uri
				uri = uri.sub(/\/\.\.\//, '/')
			end
			
			return uri_pre << uri
		else
			return uri
		end
	end	
	#default to string representation
	def to_s
		"<httpRequest>" + @uri_xml_encoded_only + "</httpRequest>\n"
	end
end

require 'test/unit/testcase'

# simple unit test for the HttpRequest class
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

class HttpRequestTest < Test::Unit::TestCase
	def test_to_s
		req = HttpRequest.new("https://")
		assert_equal("<httpRequest>https://</httpRequest>\n",req.to_s,"to_s not as expected.")
		
	end

	def test_double_slash_to_s
		req = HttpRequest.new("http://test.com//index.html")
		assert_equal("<httpRequest>http://test.com/index.html</httpRequest>\n",req.to_s,"to_s not as expected.")
		
	end

	def test_new_line_to_s
		req = HttpRequest.new("http://test.com/\n\nindex.html")
		assert_equal("<httpRequest>http://test.com/index.html</httpRequest>\n",req.to_s,"to_s not as expected.")
		
	end

	def test_path_traversal_to_s
		req = HttpRequest.new("http://test.com/../image.jpg")
		assert_equal("<httpRequest>http://test.com/image.jpg</httpRequest>\n",req.to_s,"to_s not as expected.")
		
	end

	def test_no_path_traversal_to_s
		req = HttpRequest.new("http://test.com/us/image.jpg")
		assert_equal("<httpRequest>http://test.com/us/image.jpg</httpRequest>\n",req.to_s,"to_s not as expected.")
		
	end
	
	def test_many_path_traversal_to_s
		req = HttpRequest.new("http://test.com/../../image.jpg")
		assert_equal("<httpRequest>http://test.com/image.jpg</httpRequest>\n",req.to_s,"to_s not as expected.")
		
	end
	
	def test_path_traversal_removal_to_s
		req = HttpRequest.new("http://test.com/test/test2/../image.jpg")
		assert_equal("<httpRequest>http://test.com/test/image.jpg</httpRequest>\n",req.to_s,"to_s not as expected.")
		
	end
	
	def test_do_not_follow_link_default
		req = HttpRequest.new("test")
		assert(req.follow_link, "follow link not as expected.") #default value
	end

	def test_do_not_follow_link
		req = HttpRequest.new("test")
		req.follow_link = false
		assert(!req.follow_link, "follow link not as expected.") 
	end

	def test_uri_xml_encoded_only
		req = HttpRequest.new("100>200")
		assert_equal("100&gt;200",req.uri_xml_encoded_only,"URI encoded incorrect.")
	end
end

#comment the next two lines out to enable running this unit test by executing
#ruby request/HttpRequest.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(HttpRequestTest)
