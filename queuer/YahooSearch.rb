#!/usr/bin/env ruby

# Class YahooSearch creates a list of uri's (xml representation of a HttpRequest objects)
# that result in querying keywords from the Yahoo Search API
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require "net/http"
require "uri"
require "queuer/YahooSearchConfiguration"
require "request/HttpRequest"

class YahooSearch
	#initializes Yahoo Search. Reads in configuration file, obtains and prints out http requests.
	def initialize(configuration_file_location)
		STDOUT.sync = true
		if(configuration_file_location!=nil) 
			yahoo_search_configuration = YahooSearchConfiguration.new(configuration_file_location)
			application_id = yahoo_search_configuration.application_id
			queries = yahoo_search_configuration.queries
			
			proxy_server = yahoo_search_configuration.server
			proxy_port = yahoo_search_configuration.port
			proxy_username = yahoo_search_configuration.username
			proxy_password = yahoo_search_configuration.password
			
			get_http_requests(application_id, queries, proxy_server, proxy_port, proxy_username, proxy_password)
		end
		
		@requests_thread.join
	end
	
	#obtains and prints out http requests from yahoo search api with passed in application ID
	#it queries the yahoo search api with the queries passed into this function
	def get_http_requests(application_id, queries, proxy_server, proxy_port, proxy_username, proxy_password)
		@requests_thread = Thread.new do
			puts "<httpRequests>\n"
			queries.keys.each {|query| 
				result,format  = queries[query]
				query_result = result
				start = 1
				if(result>=100)
					query_result = 100
				end
				loop do
					query_parameters = "appid="+application_id+"&format="+format+"&query="+URI.escape(query)+"&results="+query_result.to_s+"&adult_ok=1&start=" + start.to_s
					query_search_api(query_parameters,proxy_server, proxy_port, proxy_username, proxy_password)
					start = start + 100
					query_result = result-start+1 if(start+100>result+1)
					break if (start > result)
				end
			}
			puts "</httpRequests>\n"
		end
	end

	#queries the search api with the query parameters and prints out the uris obtained
	def query_search_api(query_parameters,proxy_server, proxy_port, proxy_username, proxy_password)
		request = "http://api.search.yahoo.com/WebSearchService/V1/webSearch?"+query_parameters
		# make the request
		results = ""
		begin
			url = URI.parse(request)
			if(proxy_username != "")
				results = Net::HTTP::Proxy(proxy_server, proxy_port, proxy_username, proxy_password).start(url.host,80) { |http| 
					http.request_get(url.path + "?" + url.query).body
				}
			elsif(proxy_server != "") 
				results = Net::HTTP::Proxy(proxy_server, proxy_port).start(url.host,url.port) { |http| 
					http.request_get(url.path + "?" + url.query).body
				}					
			else
				results = Net::HTTP.get_response(URI.parse(request)).body
			end
		rescue
			raise "Web services request failed"
		end
		
		doc = REXML::Document.new results;
		doc.elements.each("ResultSet/Result") { |result|
			http_request = HttpRequest.new(URI.unescape(result.elements["Url"].text)) #need to unescape as that is what is required by httprequest
			puts http_request.to_s
		}
	end
end

#public static void main?
if ARGV.length==1 and ARGV[0]=="--help"
	STDERR.puts "Usage: ruby -s queuer/YahooSearch.rb -c=[location of yahoo configuration file]"
	STDERR.puts "Query the yahoo search API for uris."
	STDERR.puts ""
	STDERR.puts "Yahoo Search Configuration File Format"
	STDERR.puts "--------------------------------------"
	STDERR.puts "<yahooSearchConfiguration xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	STDERR.puts " xsi:noNamespaceSchemaLocation=\"YahooSearchConfiguration_v1_0.xsd\""
	STDERR.puts " applicationID=\"_HoneyC_\">"
	STDERR.puts "    <query results=\"1\" format=\"ppt\">google</query>"
	STDERR.puts "    <query results=\"10\">flowers</query>"
	STDERR.puts "</yahooSearchConfiguration>"
	STDERR.puts ""
	STDERR.puts "The Yahoo search configuration specifies the application ID to be used in the "
	STDERR.puts "queries (can be obtained from http://developer.yahoo.com) as well as multiple "
	STDERR.puts "queries to be executed by the queuer. The results attribute limits the number "
	STDERR.puts "of results to be returned by the Yahoo search API. The format allows to "
	STDERR.puts "concentate on a format of value to retrieve, e.g. ppt for powerpoint presentation"
	STDERR.puts "The query value specifies the search string to be used (see http://www.yahoo.com for syntax)."
	STDERR.puts ""
	STDERR.puts "Report bugs to <https://bugs.honeynet.org/enter_bug.cgi?product=Honey-C>"
elsif $c == nil
	STDERR.puts "Usage: ruby -s queuer/YahooSearch.rb -c=[location of yahoo configuration file]"
	STDERR.puts "Try 'ruby queuer/YahooSearch.rb --help' for more information."
else
	search = YahooSearch.new($c)
end

require 'test/unit/testcase'
require 'stringio'
# Basic unit test for YahooSearch class
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php
class YahooSearchTest < Test::Unit::TestCase
	#runs a search using get_http_request function. Compares found results with previously found results
	#Note: this unit test could fail is search results change. Tried to use query params that are likely to
	#return the same uris over time.
	def test_search_tc12
		#reroute std output
		buff = StringIO.new
		$stdout = buff

		#test start
		search = YahooSearch.new("queuer/YahooSearchConfigurationUnitTest2.xml")

		#restore std output
		$stdout = STDOUT 
		
		expected_http_request1 = HttpRequest.new("http://capture-hpc.sourceforge.net/")
		expected_http_request2 = HttpRequest.new("http://honeyc.sourceforge.net/")
		
		assert_equal("<httpRequests>\n"+expected_http_request2.to_s+expected_http_request1.to_s+"</httpRequests>\n"\
		 	,buff.string,"httpRequests not as expected.")
	end

	def test_search_200results
		#reroute std output
		buff = StringIO.new
		$stdout = buff

		#test start
		search = YahooSearch.new("queuer/YahooSearchConfigurationUnitTest3.xml")
		
		#restore std output
		$stdout = STDOUT 
		
		actual_http_requests = buff.string
		actual_http_requests_count = 0
		actual_http_requests.each {|line|
		    if(line.index("<httpRequest>")!=nil)
			actual_http_requests_count = actual_http_requests_count + 1
		    end
                }
		
                #make sure there are 250 requests
		assert_equal(250,actual_http_requests_count,"Not expected number of results")
	end
	
	def test_search_1000results_tc13
		#reroute std output
		buff = StringIO.new
		$stdout = buff

		#test start
		search = YahooSearch.new("queuer/YahooSearchConfigurationUnitTest4.xml")
		
		#restore std output
		$stdout = STDOUT 
		
		actual_http_requests = buff.string
		actual_http_requests_count = 0
			actual_http_requests.each {|line|
		    if(line.index("<httpRequest>")!=nil)
			actual_http_requests_count = actual_http_requests_count + 1
		    end
                }
                
                #make sure there are 1000 requests
		assert_equal(1000,actual_http_requests_count,"Not expected number of results")
	end
	
	#def test_search_proxy_tc34
	#	#reroute std output
	#	buff = StringIO.new
	#	$stdout = buff
	#
	#	search = YahooSearch.new("queuer/YahooSearchConfigurationUnitTestProxy.xml")
	#	#restore std output
	#	$stdout = STDOUT 
	#	
	#	expected_http_request1 = HttpRequest.new("http://mail.yahoo.com/")
	#	expected_http_request2 = HttpRequest.new("http://www.google.com/")
	#	
	#	assert_equal("<httpRequests>\n"+expected_http_request2.to_s + expected_http_request1.to_s\
	#		+ "</httpRequests>\n", buff.string,"httpRequests from config not as expected")
	#end
	
	#def test_search_proxy_auth
	#	#reroute std output
	#	buff = StringIO.new
	#	$stdout = buff
	#
	#	search = YahooSearch.new("queuer/YahooSearchConfigurationUnitTestProxyAuth.xml")
	#	#restore std output
	#	$stdout = STDOUT 
	#	
	#	expected_http_request1 = HttpRequest.new("http://mail.yahoo.com/")
	#	expected_http_request2 = HttpRequest.new("http://www.google.com/")
	#	
	#	assert_equal("<httpRequests>\n"+expected_http_request2.to_s + expected_http_request1.to_s\
	#		+ "</httpRequests>\n", buff.string,"httpRequests from config not as expected")
	#end
	
	def test_search_filter_tc35
		#reroute std output
		buff = StringIO.new
		$stdout = buff

		#test start
		search = YahooSearch.new("queuer/YahooSearchConfigurationUnitTest5.xml") #filter on ppt

		#restore std output
		$stdout = STDOUT 
		
		actual_http_requests = buff.string
		end_with_ppt = true
		actual_http_requests.scan(/<httpRequest>.*?<\/httpRequest>/) { |http_request|
			is_ppt = http_request.index("ppt</httpRequest")
			is_ppt = http_request.index("pps</httpRequest") if is_ppt==nil
			if(is_ppt==nil)
				puts http_request.to_s
				end_with_ppt = false
				break
			end
		}
		assert(end_with_ppt ,"not all http reqs ended in ppt.")
	end
end

#comment the next two lines out to enable running this unit test by executing
#ruby queuer/YahooSearch.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(YahooSearchTest)
