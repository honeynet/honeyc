#!/usr/bin/env ruby

# Class SnortRulesAnalysisEngine analysises http responses against snort rules and generates a snort alerts
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require "net/http"
require "rexml/text"
require "rexml/document"
require "rexml/text"
require "thread"
require "base64"

require "analysisEngine/SnortFastAlerter"
require "analysisEngine/SnortRulesAnalysisEngineConfiguration"
require "analysisEngine/SnortRuleParser.tab"
require "analysisEngine/SnortRule"
require "analysisEngine/SnortRulesAnalysisEngineStats"
require "response/HttpResponseStats"
require "response/HttpResponse"

class SnortRulesAnalysisEngine

	#constructor. Parses configuration file and starts to get and process responses
	def initialize(configuration_file_location)
		#STDIN.binmode	
		STDIN.sync=true
		
		conf = SnortRulesAnalysisEngineConfiguration.new(configuration_file_location)
		rules_location = conf.rules_location
		snort_rule_parser = SnortRuleParser.new
		@rules = snort_rule_parser.parse_rules(rules_location)
		
		@http_responses = Queue.new
		
		get_responses
		process_responses
		
		@process_thread.join
	end
	
	#checks whether http response body matches any regex of the rules
	def analyze_response(http_response, snort_rules_analysis_engine_stats)
		match_rule = nil
		snort_rules_analysis_engine_stats.start_analysis
		@rules.each {|rule|
			if(rule.match(http_response))
				match_rule = rule
				break
			end
		}
		snort_rules_analysis_engine_stats.end_analysis(match_rule)
		return match_rule
	end
	
	#gets http responses from stdin and places them into the httpResponses object
	def get_responses
		@responses_thread = Thread.new do
			http_responses_start = gets
			loop do
				http_response_buffer = ""
				http_response_line = ""
				while http_response_line != "</httpResponse>\n"
					http_response_line = gets
					break if(http_response_line=="</httpResponses>\n")
					http_response_buffer << http_response_line.to_s
				end
				break if(http_response_line=="</httpResponses>\n")
				
				begin
					doc = REXML::Document.new http_response_buffer
					uri = doc.elements["httpResponse/uri"].text #already xml::text unnormalized
					code = doc.elements["httpResponse/code"].text #already xml::text unnormalized
					body_base64 = doc.elements["httpResponse/body"].text.to_s #not already xml::text unnormalized, because its base 64 encoded
					headers = Hash.new
					
					doc.elements.each("httpResponse/headers/header") { |header|
						key = header.attributes["name"].to_s.downcase
						headers[key]=header.text
					}
					body_base64decoded_xml_normalized = Base64.decode64(body_base64)
					body = REXML::Text.unnormalize(body_base64decoded_xml_normalized.to_s)
					http_response = HttpResponse.new(uri,code,body,headers)						
					@http_responses.push(http_response)
					@process_thread.run if @process_thread != nil
				rescue StandardError => err
					puts err.to_s + " Invalid httpResponse encountered: " + http_response_buffer
				end
				
			end
			@http_responses.push(false)
		end
	end
	
	#processes the httpResponses against the rules and generates alerts
	def process_responses
		@process_thread = Thread.new do
			#some stats
			snort_rules_analysis_engine_stats = SnortRulesAnalysisEngineStats.new
			http_response_stats = HttpResponseStats.new
			number_matches = 0
			
			#lets go
			while(http_response = @http_responses.pop)
				
				http_response_stats.add(http_response)
				snort_rules_analysis_engine_stats.add(http_response)
				
				#analyze no matter what. if 500 response, a match could still occur on the uri, aka the request
				rule_match = analyze_response(http_response, snort_rules_analysis_engine_stats)
				if rule_match != nil #only first rule match is recorded this way
					snort_fast_alert = SnortFastAlerter.output_rule_match(rule_match, http_response)
					puts snort_fast_alert.to_s
				end
				
				if http_response.code != "200 - OK"
					snort_fast_alert = SnortFastAlerter.output_general_error(http_response.code.to_s, http_response.uri)
					puts snort_fast_alert.to_s
				end
			end
			end_time = Time.now
			
			puts ""
			puts "Snort Rules Analysis Engine Statistics:"
			puts snort_rules_analysis_engine_stats.to_s
			puts "HttpResponse Statistics:"
			puts http_response_stats.to_s
		end
	end
end

#public static void main?
if ARGV.length==1 and ARGV[0]=="--help"
	STDERR.puts "Usage: ruby -s analysisEngine/SnortRulesAnalysisEngine.rb "
	STDERR.puts "            -c=[location of snort rules analysis engine configuration file]"
	STDERR.puts "Analyze http responses against snort rules and output a report."
	STDERR.puts ""
	STDERR.puts "Snort Rules Analysis Engine Configuration File Format"
	STDERR.puts "-----------------------------------------------------"
	STDERR.puts "<snortRulesAnalysisEngineConfiguration "
	STDERR.puts " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	STDERR.puts " xsi:noNamespaceSchemaLocation="
	STDERR.puts " \"SnortRulesAnalysisEngineConfiguration_v1_0.xsd\">"
	STDERR.puts "    <rulesLocation>analysisEngine/example.rules</rulesLocation>"
	STDERR.puts "</snortRulesAnalysisEngineConfiguration>"
	STDERR.puts ""
	STDERR.puts "The snort configuration file simply specifies the relative or absolute "
	STDERR.puts "location of the rules file."
	STDERR.puts ""
	STDERR.puts "Snort Rules File Format"
	STDERR.puts "-----------------------"
	STDERR.puts "alert tcp any any <> any any (msg: \"rule1\"; reference:url,http://rule1.com;"
	STDERR.puts " sid:1000001; rev:1; classtype:trojan-activity; pcre:\"/rule1pcre/\"; )"
	STDERR.puts "alert tcp any any <> any any (msg: \"google\"; reference:url,http://rule2.com;"
	STDERR.puts " sid:1000002; rev:2; classtype:attempted-dos; pcre:\"/google/\"; )"
	STDERR.puts "alert tcp any any <> any any (msg: \"rule3\"; reference:url,http://rule3.com;"
	STDERR.puts " sid:1000003; rev:1; classtype:trojan-activity; pcre:\"/rule3pcre/\"; )"
	STDERR.puts ""
	STDERR.puts "The Snort rules file format adheres to the official Snort rules format"
	STDERR.puts "(see Snort manual on http://www.snort.org). Some restrictions apply within"
	STDERR.puts "the conext of HoneyC."
	STDERR.puts "In addition to the official Snort rules format, HoneyC supports the additional "
	STDERR.puts "tag headercontent. It can be used to match on specific http response header content."
	STDERR.puts "Matching can restrict the key value pair by creating a match string in the following "
	STDERR.puts "format: headercontent:\"name=\"key\">value<. In conjunction with this new tag a new"
	STDERR.puts "pcre option H has been implemented to support pcres on header content."
	STDERR.puts ""
	STDERR.puts "Report bugs to <https://bugs.honeynet.org/enter_bug.cgi?product=Honey-C>"
elsif $c == nil
	STDERR.puts "Usage: ruby -s analysisEngine/SnortRulesAnalysisEngine.rb "
	STDERR.puts "            -c=[location of snort rules analysis engine configuration file]"
	STDERR.puts "Try 'ruby analysisEngine/SnortRulesAnalysisEngine.rb --help' for more "
	STDERR.puts "information."
else

    analysisEngine = SnortRulesAnalysisEngine.new($c)
end

#!/usr/bin/env ruby

# Class SnortRuleAnalysisEngineTest is a simple unit test of SnortRuleAnalysisEngine
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'
require 'stringio'

class SnortRulesAnalysisEngineTest < Test::Unit::TestCase
	
	def test_analyze_response_binary
		#redirect input
		#two identical http responses
		input = StringIO.new("<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"UnitTest.html</uri>\n<code>200 - OK</code>\n<headers><header name=\"content-length\">3000</header><header name=\"content-type\">jpeg</header></headers>\n<body>"\
			+"VGhpcyBpcyBhIHRlc3QgcGFnZSBmb3IgdGhlIHdlYiBicm93c2VyIHVuaXQgdGVzdC5ydWxlMnBjcmU=\n</body>\n</httpResponse>\n</httpResponses>\n")
		$stdin = input

		#redirect output
		actual_alert = StringIO.new
		$stdout = actual_alert
		contains_expected_alert = ":1000002:"
		
		snort_rules_analysis_engine = SnortRulesAnalysisEngine.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest.xml")
		$stdout = STDOUT

		assert(actual_alert.string.index(contains_expected_alert),"alert not as expected.")
	end

	
#test taking response and analyzing it against rules
	def test_analyze_response
		#redirect input
		#two identical http responses
		input = StringIO.new("<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"UnitTest.html</uri>\n<code>200 - OK</code>\n<headers></headers>\n<body>VGhpcyBpcyBhIHRlc3QgcGFnZSBmb3IgdGhlIHdlYiBicm93c2VyIHVuaXQgdGVzdC5ydWxlMnBj"\
			+"cmU=\n</body>\n</httpResponse>\n</httpResponses>\n") 
		$stdin = input

		#redirect output
		actual_alert = StringIO.new
		$stdout = actual_alert
		contains_expected_alert = ":1000002:"
		
		snort_rules_analysis_engine = SnortRulesAnalysisEngine.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest.xml")
		$stdout = STDOUT

		assert(actual_alert.string.index(contains_expected_alert),"alert not as expected.")
	end

	def test_analyze_response_tc17
		#redirect input
		input = StringIO.new("<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"UnitTest.html</uri>\n<code>200 - OK</code>\n<headers></headers>\n<body>Y29udGVudE1hdGNoDQo=\n</body>\n"\
			+"</httpResponse>\n</httpResponses>\n") 
		$stdin = input

		#redirect output
		actual_alert = StringIO.new
		$stdout = actual_alert
		contains_expected_alert = ":1000002:"
		
		snort_rules_analysis_engine = SnortRulesAnalysisEngine.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest2.xml")
		$stdout = STDOUT

		assert(actual_alert.string.index(contains_expected_alert),"alert not as expected.")

		statistic_count = 15
		
		alert_count = 0
		actual_alert.string.each {|line|
			alert_count = alert_count + 1
		}
		#make sure there is only one alert
		assert_equal(1+statistic_count,alert_count,"Not expected number of alerts")
	end

	def test_analyze_response_tc18
		#redirect input
		input = StringIO.new("<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/uriMatch"\
			+"UnitTest.html</uri>\n<code>200 - OK</code>\n<headers></headers>\n<body>&lt;!D"\
			+"OCTYPE HTML PUBLIC &quot;-//W3C//DTD HTML 4.01 Transitional//EN&quot;\r\n&quot;h"\
			+"ttp://www.w3.org/TR/html4/loose.dtd&quot;&gt;\r\n&lt;html&gt;\r\n&lt;head&gt;\r\n"\
			+"&lt;title&gt;Untitled Document&lt;/title&gt;\r\n&lt;meta http-equiv=&quot;Conte"\
			+"nt-Type&quot; content=&quot;text/html; charset=iso-8859-1&quot;&gt;\r\n&lt;/head"\
			+"&gt;\r\n\r\n&lt;body&gt;\r\nblah blah/body&gt;\r\n&lt;/html&gt;\r\n</body>\n"\
			+"</httpResponse>\n</httpResponses>\n") 
		$stdin = input

		#redirect output
		actual_alert = StringIO.new
		$stdout = actual_alert
		contains_expected_alert = ":1000003:"
		
		snort_rules_analysis_engine = SnortRulesAnalysisEngine.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest2.xml")
		$stdout = STDOUT

		assert(actual_alert.string.index(contains_expected_alert),"alert not as expected.")

		statistic_count = 15
		
		alert_count = 0
		actual_alert.string.each {|line|
			alert_count = alert_count + 1
		}
		#make sure there is only one alert
		assert_equal(1+statistic_count,alert_count,"Not expected number of alerts")
	end

	def test_analyze_response_tc19
		#redirect input
		input = StringIO.new("<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/matchRegex"\
			+"UnitTest.html</uri>\n<code>200 - OK</code>\n<headers></headers>\n<body>&lt;!D"\
			+"OCTYPE HTML PUBLIC &quot;-//W3C//DTD HTML 4.01 Transitional//EN&quot;\r\n&quot;h"\
			+"ttp://www.w3.org/TR/html4/loose.dtd&quot;&gt;\r\n&lt;html&gt;\r\n&lt;head&gt;\r\n"\
			+"&lt;title&gt;Untitled Document&lt;/title&gt;\r\n&lt;meta http-equiv=&quot;Conte"\
			+"nt-Type&quot; content=&quot;text/html; charset=iso-8859-1&quot;&gt;\r\n&lt;/head"\
			+"&gt;\r\n\r\n&lt;body&gt;\r\nblah blah/body&gt;\r\n&lt;/html&gt;\r\n</body>\n"\
			+"</httpResponse>\n</httpResponses>\n") 
		$stdin = input

		#redirect output
		actual_alert = StringIO.new
		$stdout = actual_alert
		contains_expected_alert = ":1000004:"
		
		snort_rules_analysis_engine = SnortRulesAnalysisEngine.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest2.xml")
		$stdout = STDOUT

		assert(actual_alert.string.index(contains_expected_alert),"alert not as expected.")

		statistic_count = 15
		
		alert_count = 0
		actual_alert.string.each {|line|
			alert_count = alert_count + 1
		}
		#make sure there is only one alert
		assert_equal(1+statistic_count,alert_count,"Not expected number of alerts")
	end

	def test_analyze_response_tc23
		#redirect input
		input = StringIO.new("<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/matchRegex"\
			+"uriMatchUnitTest.html</uri>\n<code>200 - OK</code>\n<headers></headers>\n<body>Y29udGVudE1hdGNoDQo=\n</body>\n"\
			+"</httpResponse>\n</httpResponses>\n") 
		$stdin = input

		#redirect output
		actual_alert = StringIO.new
		$stdout = actual_alert
		contains_expected_alert = ":1000001:"
		
		snort_rules_analysis_engine = SnortRulesAnalysisEngine.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest2.xml")
		$stdout = STDOUT

		assert(actual_alert.string.index(contains_expected_alert),"alert not as expected.")

		statistic_count = 15
		alert_count = 0
		
		actual_alert.string.each {|line|
			alert_count = alert_count + 1
		}
		#make sure there is only one alert (we break after first alert is encountered)
		assert_equal(1+statistic_count,alert_count,"Not expected number of alerts")
	end

	
	def test_analyze_response_tc20_21_22
		#redirect input
		input = StringIO.new("<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"UnitTest.html</uri>\n<code>200 - OK</code>\n<headers></headers>\n<body>&lt;!D"\
			+"OCTYPE HTML PUBLIC &quot;-//W3C//DTD HTML 4.01 Transitional//EN&quot;\r\n&quot;h"\
			+"ttp://www.w3.org/TR/html4/loose.dtd&quot;&gt;\r\n&lt;html&gt;\r\n&lt;head&gt;\r\n"\
			+"&lt;title&gt;Untitled Document&lt;/title&gt;\r\n&lt;meta http-equiv=&quot;Conte"\
			+"nt-Type&quot; content=&quot;text/html; charset=iso-8859-1&quot;&gt;\r\n&lt;/head"\
			+"&gt;\r\n\r\n&lt;body&gt;\r\nblah blah/body&gt;\r\n&lt;/html&gt;\r\n</body>\n"\
			+"</httpResponse>\n</httpResponses>\n") 
		$stdin = input

		#redirect output
		actual_alert = StringIO.new
		$stdout = actual_alert
		
		snort_rules_analysis_engine = SnortRulesAnalysisEngine.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest2.xml")
		$stdout = STDOUT

		statistic_count = 15
		alert_count = 0
		actual_alert.string.each {|line|
			alert_count = alert_count + 1
		}
		#make sure there is only one alert
		assert_equal(0+statistic_count,alert_count,"Not expected number of alerts")
	end
	
	def test_analyze_bad_response
		#redirect input
		input = StringIO.new("<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"UnitTest.html</uri>\n<code>500 - error</code>\n<headers></headers>\n<body></body>\n</httpResponse>\n</httpResponses>\n") 
		$stdin = input

		#redirect output
		actual_alert = StringIO.new
		$stdout = actual_alert
		contains_expected_alert = ":2000000:1] 500 - error"
		
		snort_rules_analysis_engine = SnortRulesAnalysisEngine.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest.xml")
		$stdout = STDOUT
		
		assert(actual_alert.string.index(contains_expected_alert),"alert not as expected.")
	end

	def test_analyze_invalid_response_tc24
		#redirect input
		input = StringIO.new("<httpResponeyc.sourceforge.net/webBrowser"\
			+"UnitTest.html\n<code>500 - error</code>\n<headers></headers>\n<body></body>\n</httpResponse>\n</httpResponses>\n") 
		$stdin = input

		#redirect output
		error_msg = StringIO.new
		$stdout = error_msg
		
		snort_rules_analysis_engine = SnortRulesAnalysisEngine.new("analysisEngine/SnortRulesAnalysisEngineConfigurationUnitTest.xml")
		$stdout = STDOUT
		
		assert(error_msg.string.index("Invalid httpResponse encountered"),"no error msg output.")
	end
end

#comment the next two lines out to enable running this unit test by executing
# ruby analysisEngine/SnortRulesAnalysisEngine.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRulesAnalysisEngineTest)