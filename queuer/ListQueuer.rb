#!/usr/bin/env ruby

# Class ListQueuer creates parses a file with a list of of uri's and outputs
# an xml representation of corresponding HttpRequest objects
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require "request/HttpRequest"
require "queuer/ListQueuerConfiguration"

class ListQueuer
	#initializes List Queuer.
	def initialize(configuration_file_location)
		STDOUT.sync = true
		if(configuration_file_location!=nil) 
			list_queuer_configuration = ListQueuerConfiguration.new(configuration_file_location)
			uris = list_queuer_configuration.uris
			
			create_http_requests(uris)
		end
		@requests_thread.join
	end
	
	#obtains and prints out xml http requests corresponding to the list of uris
	def create_http_requests(uris)
		@requests_thread = Thread.new do
			puts "<httpRequests>\n"
			uris.each {|uri| 
				http_request = HttpRequest.new(uri)
				puts http_request.to_s
			}
			puts "</httpRequests>\n"
		end
	end

end

#public static void main?
if ARGV.length==1 and ARGV[0]=="--help"
	STDERR.puts "Usage: ruby -s queuer/QueuerList.rb -c=[location of list queuer configuration file]"
	STDERR.puts "Parses a static list of unencoded uris. The uris can optionally be url encoded, but must be XML encoded."
	STDERR.puts ""
	STDERR.puts "List Ququer Configuration File Format"
	STDERR.puts "--------------------------------------"
	STDERR.puts "<listQueuerConfiguration xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	STDERR.puts " xsi:noNamespaceSchemaLocation=\"ListQueuerConfiguration_v1_0.xsd\">"
	STDERR.puts "    <uri>http://www.google.com</uri>"
	STDERR.puts "    <uri>http://honeyc.sourceforge.net/index.html?test=one and two&amp;test2=two</uri>"
	STDERR.puts "    <uri>http://honeyc.sourceforge.net/index.html?test=one%20and%20two&amp;test2=two</uri>"
	STDERR.puts "</listQueuerConfiguration>"
	STDERR.puts ""
	STDERR.puts "Report bugs to <https://bugs.honeynet.org/enter_bug.cgi?product=Honey-C>"
elsif $c == nil
	STDERR.puts "Usage: ruby -s queuer/ListQueuer.rb -c=[location of list queuer configuration file]"
	STDERR.puts "Try 'ruby queuer/ListQueuer.rb --help' for more information."
else
	search = ListQueuer.new($c)
end

require 'test/unit/testcase'
require 'stringio'
# Basic unit test for ListQueuer class
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php
class ListQueuerTest < Test::Unit::TestCase
	def test_list_queuer_tc36
		#reroute std output
		buff = StringIO.new
		$stdout = buff

		#test start
		search = ListQueuer.new("queuer/ListQueuerConfigurationUnitTest.xml")

		#restore std output
		$stdout = STDOUT 
		
		expected_http_request1 = HttpRequest.new("http://www.unit.com")
		expected_http_request2 = HttpRequest.new("http://www.unittest.com/index.html?sometest=one&amp;otherparam=one and two")
		expected_http_request3 = HttpRequest.new("http://www.unittest.com/index.html?sometest=one&amp;otherparam=three and two")
		
		assert_equal("<httpRequests>\n"+expected_http_request1.to_s+expected_http_request2.to_s+expected_http_request3.to_s+"</httpRequests>\n"\
		 	,buff.string,"httpRequests not as expected.")
	end
end

#comment the next two lines out to enable running this unit test by executing
#ruby queuer/ListQueuer.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(ListQueuerTest)
