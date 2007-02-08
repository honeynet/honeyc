#!/usr/bin/env ruby

# Class SnortRulesAnalysisEngineStats is a module that allows to collect some stats on snort rule analysis objects
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'response/HttpResponse'

class SnortRulesAnalysisEngineStats
	attr_accessor :all_count, :start_time, :analysis_time_sum, :matches_count
	
	def initialize()
		@all_count = 0
		@start_time = Time.now
		@analysis_time_sum = 0
		@matches_count = 0
	end
	
	def add(http_response)
		if(http_response!=nil)
			update_count(http_response)
		end
	end
	
	def start_analysis()
		@start_analysis_time = Time.now
	end
	
	def end_analysis(match)
		@matches_count = @matches_count + 1 if (match!=nil and match!=false)
		
		@end_analysis_time = Time.now
		@analysis_time_sum = @analysis_time_sum + (@end_analysis_time - @start_analysis_time)
	end
	
	def update_count(http_response)
		@all_count = @all_count + 1
	end
	
	#get all stats
	def to_s
		current_time = Time.now
	
		average_time = "ndef"
		average_size = @analysis_time_sum/@all_count if @all_count != 0
		
		"Analyzed " + @all_count.to_s + " responses in " + (current_time - @start_time).to_s + "\n"\
		+ "Matches found " + @matches_count.to_s + "\n"\
		+ "Average Analysis Time: " + average_size.to_s + "\n"
	end
	
end

require 'test/unit/testcase'


# simple unit test for the SnortRulesAnalysisEngineStats class
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

class SnortRulesAnalysisEngineStatsTest < Test::Unit::TestCase
	def test_all_count
		stats = SnortRulesAnalysisEngineStats.new
		headers1 = Hash["content-type"=>"text/html","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"0"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		assert_equal(3,stats.all_count,"All count incorrect.")
	end
	
	def test_matches_count
		stats = SnortRulesAnalysisEngineStats.new
		headers1 = Hash["content-type"=>"text/html","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		stats.start_analysis
		stats.end_analysis(true)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"0"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		stats.start_analysis
		stats.end_analysis(true)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		stats.start_analysis
		stats.end_analysis(false)
		assert_equal(2,stats.matches_count,"Match count incorrect.")
	end
	
	def test_analysis_time_sum
		stats = SnortRulesAnalysisEngineStats.new
		headers1 = Hash["content-type"=>"text/html","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		stats.start_analysis
		sleep 1
		stats.end_analysis(true)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"0"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		stats.start_analysis
		sleep 2
		stats.end_analysis(true)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		stats.start_analysis
		sleep 3
		stats.end_analysis(false)
		assert(stats.analysis_time_sum > 5,"Analysis Time Sum incorrect.")
	end
	
	def test_to_s
		stats = SnortRulesAnalysisEngineStats.new
		headers1 = Hash["content-type"=>"text/html","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		stats.start_analysis
		sleep 1
		stats.end_analysis(true)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"0"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		stats.start_analysis
		sleep 2
		stats.end_analysis(true)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		stats.start_analysis
		sleep 3
		stats.end_analysis(false)
		
		expected_str = "Analyzed 3 responses in XX.YY\nMatches found 2\nAverage Analysis Time: XX.YY\n"
		actual_str_without_time = stats.to_s.sub(/[0-9]*\.[0-9]*\n/,"XX.YY\n")
		actual_str_without_time = actual_str_without_time.to_s.sub(/[0-9]*\.[0-9]*\n/,"XX.YY\n")
		assert_equal(expected_str, actual_str_without_time,"stats to_s incorrect.")
	end
end

#comment the next two lines out to enable running this unit test by executing
#ruby analysisEngine/SnortRulesAnalysisEngineStats.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(SnortRulesAnalysisEngineStatsTest)