#!/usr/bin/env ruby

# Class HttpRequestStats is a module that allows to collect some stats on HttpResponse objects
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'response/HttpResponse'

class HttpResponseStats
	attr_accessor :all_count, :length_count, :length_sum, :error_code_count, :content_type_count, :content_type_length_sum
	
	def initialize()
		@all_count = 0
		@src_count = 0 #count of urls referenced by the target pages
		@length_count = 0
		@length_sum = 0
		@content_type_count = Hash.new
		@error_code_count = Hash.new
		@content_type_length_sum = Hash.new
	end
	
	def add(http_response)
		if(http_response!=nil)
			update_count(http_response)
			update_length(http_response)
		end
	end
	
	def update_count(http_response)
		@all_count = @all_count + 1
		
		error_code = http_response.code
		if(@error_code_count.key?(error_code))
			current_error_code_count = @error_code_count[error_code]
			@error_code_count[error_code] = current_error_code_count + 1
		else
			@error_code_count[error_code] = 1
		end
		
		if(http_response.code==200 || http_response.code.to_s.index("200"))
			headers = http_response.headers
			content_type = headers["content-type"]
			if(@content_type_count.key?(content_type))
				current_content_type_count = @content_type_count[content_type]
				@content_type_count[content_type] = current_content_type_count + 1
			else
				@content_type_count[content_type] = 1
			end
		end
	end
	
	#includes update of length count
	#only OK responses
	def update_length(http_response)
		if(http_response.code==200 || http_response.code.to_s.index("200"))
			@length_count = @length_count + 1
		
			headers = http_response.headers
			content_length = headers["content-length"].to_i
			
			if(content_length != nil && content_length !=0)
				@length_sum = @length_sum + content_length 
				
				content_type = headers["content-type"]
				if(@content_type_length_sum.key?(content_type))
					current_content_type_length_sum = @content_type_length_sum[content_type]
					@content_type_length_sum[content_type] = current_content_type_length_sum + content_length
				else
					@content_type_length_sum[content_type] = content_length
				end
			end
		end
	end
		
	#get all stats
	def to_s
		error_code_count = "["
		@error_code_count.keys.each do | error_code |
			count = @error_code_count[error_code]
			error_code_count << "\n\t-" + error_code.to_s + ": " + count.to_s + "-"
		end
		error_code_count << "\n]"
	
		content_type_count = "["
		content_type_length_averages = "["
		@content_type_count.keys.each do | content_type |
			count = @content_type_count[content_type]
			length_sum = @content_type_length_sum[content_type]
			if(length_sum!=nil)
				average = length_sum/count
				content_type_count << "\n\t-" + content_type.to_s + ": " + count.to_s + "-"
				content_type_length_averages << "\n\t-" + content_type.to_s + ": " + average.to_s + "-"
			end
		end
		content_type_length_averages << "\n]"
		content_type_count << "\n]"
	
		average_size = "ndef"
		average_size = @length_sum/@length_count if @length_count != 0
		
		"All Count: " + @all_count.to_s + "\n"\
		+ "Average Size (200-OK): " + average_size.to_s + "\n"\
		+ "Error Code Count: " + error_code_count.to_s + "\n"\
		+ "Content Type Count: " + content_type_count.to_s + "\n"\
		+ "Content Type Length Averages: " + content_type_length_averages.to_s + "\n"
	end
	
end

require 'test/unit/testcase'


# simple unit test for the HttpRequestStats class
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

class HttpResponseStatsTest < Test::Unit::TestCase
	def test_all_count
		stats = HttpResponseStats.new
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
	
	def test_length_count
		stats = HttpResponseStats.new
		headers1 = Hash["content-type"=>"text/html","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"0"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		assert_equal(2,stats.length_count,"Length count incorrect.")
	end
	
	def test_length_sum
		stats = HttpResponseStats.new
		headers1 = Hash["content-type"=>"text/html","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"0"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		assert_equal(5000,stats.length_sum,"Length sum incorrect.")
	end
	
	def test_error_code_count
		stats = HttpResponseStats.new
		headers1 = Hash["content-type"=>"text/html","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"0"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		headers4 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res4 = HttpResponse.new("test3",501,"&body",headers4)
		stats.add(res4)
		headers5 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res5 = HttpResponse.new("test3",404,"&body",headers5)
		stats.add(res5)
		assert_equal(2,stats.error_code_count[404],"404 error code count incorrect.")
		assert_equal(1,stats.error_code_count[501],"501 error code count incorrect.")
	end

	def test_content_type_count
		stats = HttpResponseStats.new
		headers1 = Hash["content-type"=>"application/jpg","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"10000"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		headers4 = Hash["content-type"=>"text/html","content-length"=>"1000"]
		res4 = HttpResponse.new("test3",200,"&body",headers4)
		stats.add(res4)
		headers5 = Hash["content-type"=>"text/html","content-length"=>"150"]
		res5 = HttpResponse.new("test3",200,"&body",headers5)
		stats.add(res5)
		assert_equal(3,stats.content_type_count["text/html"],"Content type count text/html incorrect.")
		assert_equal(1,stats.content_type_count["application/jpg"],"Content type count application/jpg incorrect.")
	end
	
	def test_content_type_length_sum
		stats = HttpResponseStats.new
		headers1 = Hash["content-type"=>"application/jpg","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"10000"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		headers4 = Hash["content-type"=>"text/html","content-length"=>"1000"]
		res4 = HttpResponse.new("test3",200,"&body",headers4)
		stats.add(res4)
		headers5 = Hash["content-type"=>"text/html","content-length"=>"150"]
		res5 = HttpResponse.new("test3",200,"&body",headers5)
		stats.add(res5)
		assert_equal(3150,stats.content_type_length_sum["text/html"],"Content type length_sum text/html incorrect.")
		assert_equal(3000,stats.content_type_length_sum["application/jpg"],"Content type length_sum application/jpg incorrect.")
	end
	
	def test_to_s
		stats = HttpResponseStats.new
		headers1 = Hash["content-type"=>"application/jpg","content-length"=>"3000"]
		res1 = HttpResponse.new("test1",200,"&body",headers1)
		stats.add(res1)
		headers2 = Hash["content-type"=>"text/html","content-length"=>"10000"]
		res2 = HttpResponse.new("test2",404,"",headers2)
		stats.add(res2)
		headers3 = Hash["content-type"=>"text/html","content-length"=>"2000"]
		res3 = HttpResponse.new("test3",200,"&body",headers3)
		stats.add(res3)
		headers4 = Hash["content-type"=>"text/html","content-length"=>"1000"]
		res4 = HttpResponse.new("test3",200,"&body",headers4)
		stats.add(res4)
		headers5 = Hash["content-type"=>"text/html","content-length"=>"150"]
		res5 = HttpResponse.new("test3",200,"&body",headers5)
		stats.add(res5)
		
		actual_string = stats.to_s
		expected_string = "All Count: 5\nAverage Size (200-OK): 1537\nError Code Count: [\n\t-200: 4-\n\t-404: 1-\n]\n"\
			+ "Content Type Count: [\n\t-text/html: 3-\n\t-application/jpg: 1-\n]\nContent Type Length Ave"\
			+ "rages: [\n\t-text/html: 1050-\n\t-application/jpg: 3000-\n]\n"
		assert_equal(expected_string, actual_string, "to_s not as expected")
	end
end

#comment the next two lines out to enable running this unit test by executing
#ruby response/HttpResponseStats.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(HttpResponseStatsTest)