#!/usr/bin/env ruby

# Class WebBrowser makes simple web requests and returns the resulting page
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require "net/http"
require "uri"
require "rexml/text"
require "thread"
require "timeout"
require "request/HttpRequest"
require "response/HttpResponse"
require "visitor/WebBrowserConfiguration"
require "utils/ThreadPool"

class ThreadPool
	def exception(thread, err, *original_args)
		begin
		http_request = original_args[0]
		browser = original_args[1]
		
		case err.class.to_s
			when "URI::InvalidURIError"
				http_response = HttpResponse.new(http_request.uri,"400 - Bad request: " + err.to_s,"", Hash.new)
				browser.output_http_response(http_response)
			when "Timeout::Error"
				http_response = HttpResponse.new(http_request.uri,"408 - Timeout Error","", Hash.new)
				browser.output_http_response(http_response)
			else
				#todo - if error is dns issue, add logic to have servers in this category not visited in the future.
				host = URI.parse(http_request.uri).host
				browser.non_exist_servers.shift if(browser.non_exist_servers.size>browser.non_exist_servers_max_size)
				browser.non_exist_servers.push(host) if(err.to_s.index("getaddrinfo")) #host name unknow
				
				http_response = HttpResponse.new(http_request.uri,"501 - " + err.to_s,"", Hash.new)
				browser.output_http_response(http_response)
		end
		rescue StandardError => e
			STDERR.puts "Error: " + e.to_s
		end
	end  
end

class WebBrowser
	attr_accessor :non_exist_servers, :non_exist_servers_max_size, :timeout
	
	#constructor. Parses configuration file and starts to get and makes requests
	def initialize(configuration_file_location)
		STDOUT.binmode
		STDIN.sync = true
		STDOUT.sync = true
		@timeout = 30
	
		@non_exist_servers = Array.new
		@non_exist_servers_max_size = 10000
		
		@uri_cache_max_size = 10000                          
		@uri_cache = Array.new
		@uri_cache_mutex = Mutex.new
		
		web_browser_configuration = WebBrowserConfiguration.new(configuration_file_location)
		follow_a_link = web_browser_configuration.follow_a_link
		browser_threads = web_browser_configuration.browser_threads
		user_agent = web_browser_configuration.user_agent
		proxy_server = web_browser_configuration.server
		proxy_port = web_browser_configuration.port
		proxy_username = web_browser_configuration.username
		proxy_password = web_browser_configuration.password
		
		@url_filter = Regexp.compile(web_browser_configuration.url_filter) if web_browser_configuration.url_filter!=nil
		
		@thread_pool = ThreadPool.new(browser_threads)		
		@http_requests = SizedQueue.new(browser_threads*5)
		@output_buffer_mutex = Mutex.new
		
		@pages_thread_alive = true
		get_uris
		get_pages(user_agent, browser_threads, follow_a_link, proxy_server, proxy_port, proxy_username, proxy_password)
		@pages_thread.join
		@uris_thread.join
		@thread_pool.shutdown
		puts "</httpResponses>"
	end
	
	
	
	#gets http requests from stdin and places them into the httpRequests object
	def get_uris
		uri_start = "<httpRequest>".length
		@uris_thread = Thread.new do
			http_requests_start = gets
			if(http_requests_start.index("<httpRequests>")==nil)
				raise ArgumentError, "Invalid httpRequest encountered: " + http_requests_start.to_s
			end
			
			loop do
				http_request_xml = gets
				if(http_request_xml.index("<httpRequest>")==nil and http_request_xml.index("</httpRequest>")==nil\
					and http_request_xml.index("</httpRequests>")==nil)
					raise ArgumentError, "Invalid httpRequest encountered: " + http_request_xml.to_s
				end
				break if(http_request_xml.index("</httpRequests>")!=nil)
				uri_end = http_request_xml.rindex("</httpRequest>")
				uri = REXML::Text.unnormalize(http_request_xml[uri_start..uri_end-1])
				http_request = HttpRequest.new(uri)
				@http_requests.push(http_request)
				@pages_thread.run if @pages_thread != nil
			end
			sleep 1
			while(@pages_thread_alive || !@thread_pool.empty?)
				sleep 1
			end
			@http_requests.push(false)
		end
	end
	
	#makes the requests that exist in the http requests array
	def get_pages(user_agent, browser_threads, follow_a_link, proxy_server, proxy_port, proxy_username, proxy_password)
		@pages_thread = Thread.new do
			puts "<httpResponses>"
			while(tmp_http_request = @http_requests.pop)
				@thread_pool.dispatch(tmp_http_request, self) do |http_request, browser|
					url = URI.parse(URI.escape(http_request.uri)) #url encoding happens here
					already_visited = false
					@uri_cache_mutex.synchronize do
					    already_visited = @uri_cache.include?(url)
					    @uri_cache.shift if(@uri_cache.size>@uri_cache_max_size)
					    @uri_cache.push(url)
					end
					
					if(!already_visited)
					    url_tmp = url
					    follow_redirects = 10
							
					    loop do 
						    raise "host name unknown" if @non_exist_servers.include?(url_tmp.host)
						    path = url_tmp.path
						    path = "/" if path == "" #needed because otherwise error msg of empty req path results
						    query = "?" + URI.escape(url_tmp.query.to_s) if url_tmp.query != nil
						    
									    
						    if(proxy_username != "")
							    results = Net::HTTP::Proxy(proxy_server, proxy_port, proxy_username, proxy_password).start(url_tmp.host,url_tmp.port) { |http| 
								    http.read_timeout = @timeout 
								    http.request_get(path + query.to_s, {'User-Agent' => user_agent})
							    }
						    elsif(proxy_server != "") 
							    results = Net::HTTP::Proxy(proxy_server, proxy_port).start(url_tmp.host,url_tmp.port) { |http| 
								    http.read_timeout = @timeout 
								    http.request_get(path + query.to_s, {'User-Agent' => user_agent})
							    }					
						    else
							    results = Net::HTTP.start(url_tmp.host,url_tmp.port) { |http| 
								    http.read_timeout = @timeout 
								    http.request_get(path + query.to_s, {'User-Agent' => user_agent})
							    }
						    end
						
						    case results
							    when Net::HTTPSuccess
								    http_response = HttpResponse.new(http_request.uri,results.code.to_s + " - OK",results.body, results.to_hash)
								    if(http_request.follow_link)
									    results.body.scan(/src\s*=\s*\"(.*?)\"/im) { |links|  
										    for link in links 
											    link = WebBrowser.build_url(url_tmp.scheme + "://" + url_tmp.host.to_s + path, link)
											    inline_http_request = HttpRequest.new(link)
											    inline_http_request.follow_link = false
											    @http_requests.push(inline_http_request) if(!WebBrowser.filtered?(@url_filter,link))
										    end
									    }
									    results.body.scan(/data\s*=\s*\"(.*?)\"/im) { |links|  
										    for link in links 
											    link = WebBrowser.build_url(url_tmp.scheme + "://" + url_tmp.host.to_s + path, link)
											    inline_http_request = HttpRequest.new(link)
											    inline_http_request.follow_link = false
											    @http_requests.push(inline_http_request) if(!WebBrowser.filtered?(@url_filter,link))
										    end
									   }
								    end
								    output_http_response(http_response)
								    break
							    when Net::HTTPRedirection 
								    redirect_location = WebBrowser.build_url(url_tmp.scheme + "://" + url_tmp.host.to_s + path, results['location'])											    
								    url_tmp = URI.parse(URI.escape(redirect_location.to_s))
								    
								    follow_redirects= follow_redirects - 1
								    if(follow_redirects < 0)
									    http_response = HttpResponse.new(http_request.uri,results.code.to_s + " - Too many redirects.","", Hash.new)
									    output_http_response(http_response)
									    break
								    end
							    else
								    http_response = HttpResponse.new(http_request.uri,results.code.to_s + " - " + results.message.to_s,"", Hash.new)
								    output_http_response(http_response)
								    break
								
						       end
					       end
					end
				end
			end
		end
		@pages_thread_alive = false
		

	end
	
	def output_http_response(http_response)
		@output_buffer_mutex.synchronize do
			#STDERR.puts http_response.to_s
			puts http_response.to_s
		end
	end
	
	def WebBrowser.filtered?(url_filter,uri)
		return false if url_filter == nil
		return url_filter=~uri 
	end
	
	#takes a current url that might contain a link and builds a resulting url
	#link_url could be relative at which point some information from the current url
	#needs to be taken into account
	#takes unescaped urls
	def WebBrowser.build_url(current_url_str, link_url_str)
		current_url = URI.parse(URI.escape(current_url_str))
		current_host = current_url.host
		current_port = current_url.port
		current_path = current_url.path
		current_scheme = current_url.scheme
		
		if(link_url_str.index("%")!=nil)
			link_url_str = URI.unescape(link_url_str)
		end
		
		result_url = ""
		if(link_url_str.index("http://")==0 || link_url_str.index("https://")==0)
			result_url = link_url_str
		elsif (link_url_str.index("/")==0)
			result_url = current_scheme + "://" + current_host + link_url_str
		elsif (link_url_str.index("./")==0)
			if(current_path == nil || current_path[-1]==47 || current_path.index(".")==nil) #e.g. http://www.sf.net/test/ or  http://www.sf.net/test
				current_path = current_path + '/' if(current_path[-1]!=47) #47 = '/'
				result_url = current_scheme + "://"+current_host+current_path+link_url_str[2..-1]
			else #e.g. http://www.sf.net/test/index.html
				current_path = current_path[0..current_path.rindex('/')]
				result_url = current_scheme + "://"+current_host+current_path+link_url_str[2..-1]			
			end
		else
			if(current_path == nil || current_path[-1]==47 || current_path.index(".")==nil) #e.g. http://www.sf.net/test/ or  http://www.sf.net/test
				current_path = current_path + '/' if(current_path[-1]!=47) #47 = '/'
				result_url = current_scheme + "://"+current_host+current_path+link_url_str[0..-1]
			else #e.g. http://www.sf.net/test/index.html
				current_path = current_path[0..current_path.rindex('/')]
				result_url = current_scheme + "://"+current_host+current_path+link_url_str[0..-1]			
			end
		end
		
		return result_url
	end
end

#public static void main?
if ARGV.length==1 and ARGV[0]=="--help"
	STDERR.puts "Usage: ruby -s visitor/WebBrowser.rb -c=[location of web browser configuration file]"
	STDERR.puts "Get http responses for a bunch of uris."
	STDERR.puts ""
	STDERR.puts "Web Browser Configuration File Format"
	STDERR.puts "-------------------------------------"
	STDERR.puts "<webBrowserConfiguration xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	STDERR.puts " xsi:noNamespaceSchemaLocation=\"WebBrowserConfiguration_v1_0.xsd\">"
	STDERR.puts "    <userAgent>Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)</userAgent>"
	STDERR.puts "    <followALink>true</followALink>"
	STDERR.puts "    <browserThreads>20</browserThreads>"
	STDERR.puts "    <proxy>"
	STDERR.puts "	    <server></server>"
	STDERR.puts "	    <port></port>"
	STDERR.puts "	    <username></username>"
	STDERR.puts "	    <password></password>"
	STDERR.puts "    </proxy>"
	STDERR.puts "</webBrowserConfiguration>"
	STDERR.puts ""
	STDERR.puts "The web browser configuration file simply specifies the user agent header "
	STDERR.puts "to be used when making requests. It also allows to specify how many concurrent "
	STDERR.puts "threads should be used to retrieve web pages. This value defaults to 20, but "
	STDERR.puts "it is recommended to vary the value in a tuning session to find the optimum "
	STDERR.puts "value for your connection speed and machines performance."
	STDERR.puts "The web browser can also expand onto the links contained in the responses of the "
	STDERR.puts "requests from the queuer. This, at this point in time, is more a short cut to "
	STDERR.puts "not have to implement a full fledged crawler as a queuer."
	STDERR.puts ""
	STDERR.puts "Report bugs to <https://bugs.honeynet.org/enter_bug.cgi?product=Honey-C>"
elsif $c == nil
	STDERR.puts "Usage: ruby -s visitor/WebBrowser.rb -c=[location of web browser configuration file]"
	STDERR.puts "Try 'ruby visitor/WebBrowser.rb --help' for more information."
else
	browser = WebBrowser.new($c)
end

#!/usr/bin/env ruby

# Class WebBrowserTest is a simple unit test of WebBrowser
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'
require 'stringio'

class WebBrowserTest < Test::Unit::TestCase

	def test_filter
		filter = Regexp.compile("jpg|gif")
		filtered = WebBrowser.filtered?(filter,"http://www.google.com/image.gif")
		
		assert(filtered,"url not filtered")
	end
	
	def no_filter
		filter = Regexp.compile("jpg|gif")
		filtered = WebBrowser.filtered?(filter,"http://www.google.com/index.html")
		
		assert(!filtered,"url filtered")
	end

	def test_build_url_new_url
		current_url = "http://honeyc.sf.net"
		link_url = "http://www.google.com/test?search=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://www.google.com/test?search=foo",result_url,"build url doesnt return the new url.")
	end
	
	def test_build_url_absolute
		current_url = "http://honeyc.sf.net"
		link_url = "/newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end
	
	def test_build_url_absolute_encoded
		current_url = "http://honeyc.sf.net"
		link_url = "/newpath?test=sth%20space"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/newpath?test=sth space",result_url,"build url doesnt return absolute url.")
	end
	
	def test_build_url_relative_one
		current_url = "http://honeyc.sf.net/test/"
		link_url = "./newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/test/newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end

	def test_build_url_relative_two
		current_url = "http://honeyc.sf.net/test"
		link_url = "./newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/test/newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end
	
	def test_build_url_relative_three
		current_url = "http://honeyc.sf.net"
		link_url = "./newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end
	
	def test_build_url_relative_four
		current_url = "http://honeyc.sf.net/"
		link_url = "./newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end

	def test_build_url_relative_five
		current_url = "http://honeyc.sf.net/index.html"
		link_url = "./newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end
	
	def test_build_url_relative_six
		current_url = "http://honeyc.sf.net/test/index.html"
		link_url = "./newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/test/newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end
	
	def test_build_url_relative_seven
		current_url = "http://honeyc.sf.net/test/index.html/"
		link_url = "./newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/test/index.html/newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end

	def test_build_url_relative_seven
		current_url = "http://honeyc.sf.net/test/test2/index.html"
		link_url = "../../newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/test/test2/../../newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end
	
	def test_build_url_relative_eight
		current_url = "http://honeyc.sf.net/test/index.html/"
		link_url = "newpath?test=foo"
		
		result_url = WebBrowser.build_url(current_url,link_url)
		assert_equal("http://honeyc.sf.net/test/index.html/newpath?test=foo",result_url,"build url doesnt return absolute url.")
	end
	
	#test non existant server
	def test_visit_to_nonexisting_server_tc5
		#redirect input
		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://www.isuredontexist3421.com/</httpRequest>\n"\
			+ "<httpRequest>http://www.isuredontexist3421.com/someotherurl.html</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input

		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		
		expected_http_response1 = "<code>501 - getaddrinfo" #original error
		expected_http_response2 = "<code>501 - host name unknown" #custom cache error
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
		
		
		error_response1 = actual_http_response.string.index(expected_http_response1)
		error_response2 = actual_http_response.string.index(expected_http_response2)
		
		assert(error_response1,"http response1 not as expected.")
		assert(error_response2,"http response2 not as expected.")
	end
	
	def test_double_visit_same_url
	    	input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net/webBrowserUnitTest.html?dummmyVar1=1&amp;dummyVar2=2</httpRequest>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net/webBrowserUnitTest.html?dummmyVar1=1&amp;dummyVar2=2</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input

		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"UnitTest.html?dummmyVar1=1&amp;dummyVar2=2</uri>\n<code>200 - OK</code>\n<header"\
			+"s><header name=\"last-modified\">Fri, 06 Oct 2006 04:09:52 GMT</header>\n<header"\
			+" name=\"connection\">close</header>\n<header name=\"date\">removed</header>\n<he"\
			+"ader name=\"etag\">&quot;7c1245-de-4525d710&quot;</header>\n<header name=\"conte"\
			+"nt-type\">text/html</header>\n<header name=\"server\">Apache/1.3.33 (Unix) PHP/4"\
			+".3.10</header>\n<header name=\"content-length\">222</header>\n<header name=\"x-p"\
			+"ad\">avoid browser bug</header>\n<header name=\"accept-ranges\">bytes</header>\n"\
			+"</headers>\n<body>Jmx0O2h0bWwmZ3Q7DQombHQ7aGVhZCZndDsNCiZsdDt0aXRsZSZndDtVbnRp\n"\
			+"dGxlZCBEb2N1bWVudCZsdDsvdGl0bGUmZ3Q7DQombHQ7bWV0YSBodHRwLWVx\ndWl2PSZxdW90O0Nvbn"\
			+"RlbnQtVHlwZSZxdW90OyBjb250ZW50PSZxdW90O3Rl\neHQvaHRtbDsgY2hhcnNldD1pc28tODg1OS0x"\
			+"JnF1b3Q7Jmd0Ow0KJmx0Oy9o\nZWFkJmd0Ow0KDQombHQ7Ym9keSZndDsNClRoaXMgaXMgYSB0ZXN0IH"\
			+"BhZ2Ug\nZm9yIHRoZSB3ZWIgYnJvd3NlciB1bml0IHRlc3QucnVsZTJwY3JlDQombHQ7\nL2JvZHkmZ3"\
			+"Q7DQombHQ7L2h0bWwmZ3Q7DQo=\n</body>\n</httpResponse>\n</httpResponses>\n"
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
		
		#although two requests, one response, since request should have been cached.
		date_str = Regexp.escape("<header name=\"date\">.*?<\/header>")
		actual_http_response_without_date = actual_http_response.string.to_s.sub(/<header name=\"date\">.*?<\/header>/,"<header name=\"date\">removed</header>")
		assert_equal(expected_http_response,actual_http_response_without_date,"http response not as expected.")
	end
	
	#input http request and make sure http response is output
	#covers functional test case 2
	def test_visit_tc2
#redirect input
		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net/webBrowserUnitTest.html?dummmyVar1=1&amp;dummyVar2=2</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input

		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"UnitTest.html?dummmyVar1=1&amp;dummyVar2=2</uri>\n<code>200 - OK</code>\n<header"\
			+"s><header name=\"last-modified\">Fri, 06 Oct 2006 04:09:52 GMT</header>\n<header"\
			+" name=\"connection\">close</header>\n<header name=\"date\">removed</header>\n<he"\
			+"ader name=\"etag\">&quot;7c1245-de-4525d710&quot;</header>\n<header name=\"conte"\
			+"nt-type\">text/html</header>\n<header name=\"server\">Apache/1.3.33 (Unix) PHP/4"\
			+".3.10</header>\n<header name=\"content-length\">222</header>\n<header name=\"x-p"\
			+"ad\">avoid browser bug</header>\n<header name=\"accept-ranges\">bytes</header>\n"\
			+"</headers>\n<body>Jmx0O2h0bWwmZ3Q7DQombHQ7aGVhZCZndDsNCiZsdDt0aXRsZSZndDtVbnRp\n"\
			+"dGxlZCBEb2N1bWVudCZsdDsvdGl0bGUmZ3Q7DQombHQ7bWV0YSBodHRwLWVx\ndWl2PSZxdW90O0Nvbn"\
			+"RlbnQtVHlwZSZxdW90OyBjb250ZW50PSZxdW90O3Rl\neHQvaHRtbDsgY2hhcnNldD1pc28tODg1OS0x"\
			+"JnF1b3Q7Jmd0Ow0KJmx0Oy9o\nZWFkJmd0Ow0KDQombHQ7Ym9keSZndDsNClRoaXMgaXMgYSB0ZXN0IH"\
			+"BhZ2Ug\nZm9yIHRoZSB3ZWIgYnJvd3NlciB1bml0IHRlc3QucnVsZTJwY3JlDQombHQ7\nL2JvZHkmZ3"\
			+"Q7DQombHQ7L2h0bWwmZ3Q7DQo=\n</body>\n</httpResponse>\n</httpResponses>\n"
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
		
		date_str = Regexp.escape("<header name=\"date\">.*?<\/header>")
		actual_http_response_without_date = actual_http_response.string.to_s.sub(/<header name=\"date\">.*?<\/header>/,"<header name=\"date\">removed</header>")
		assert_equal(expected_http_response,actual_http_response_without_date,"http response not as expected.")
	end
	
	
	def test_visit_relative_src_tc32
#redirect input
		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net/webBrowserUnitTestRelativeSrc.html</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input

		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"UnitTestRelativeSrc.html</uri>\n<code>200 - OK</code>\n<headers><header name=\"l"\
			+"ast-modified\">Thu, 19 Oct 2006 01:23:04 GMT</header>\n<header name=\"connection"\
			+"\">close</header>\n<header name=\"date\">removed</header>\n<header name=\"etag\""\
			+">&quot;7c1225-11b-4536d378&quot;</header>\n<header name=\"content-type\">text/ht"\
			+"ml</header>\n<header name=\"server\">Apache/1.3.33 (Unix) PHP/4.3.10</header>\n<"\
			+"header name=\"content-length\">283</header>\n<header name=\"x-pad\">avoid browse"\
			+"r bug</header>\n<header name=\"accept-ranges\">bytes</header>\n</headers>\n<body"\
			+">Jmx0O2h0bWwmZ3Q7DQombHQ7aGVhZCZndDsNCiZsdDt0aXRsZSZndDtVbnRp\ndGxlZCBEb2N1bWVud"\
			+"CZsdDsvdGl0bGUmZ3Q7DQombHQ7bWV0YSBodHRwLWVx\ndWl2PSZxdW90O0NvbnRlbnQtVHlwZSZxdW9"\
			+"0OyBjb250ZW50PSZxdW90O3Rl\neHQvaHRtbDsgY2hhcnNldD1pc28tODg1OS0xJnF1b3Q7Jmd0Ow0KJ"\
			+"mx0Oy9o\nZWFkJmd0Ow0KDQombHQ7Ym9keSZndDsNClRoaXMgaXMgYSB0ZXN0IHBhZ2Ug\nZm9yIHRoZ"\
			+"SB3ZWIgYnJvd3NlciB1bml0IHRlc3Qgd2l0aCBhIHJlbGF0aXZl\nIHNyYyB0byBhIGphdmFzY3JpcHQ"\
			+"gZmlsZS4NCiZsdDsvYm9keSZndDsNCiZs\ndDsvaHRtbCZndDsNCiZsdDtzY3JpcHQgc3JjPSZxdW90O"\
			+"3Rlc3RTY3JpcHQu\nanMmcXVvdDsvJmd0Ow==\n</body>\n</httpResponse>\n<httpResponse>\n"\
			+"<uri>http://honeyc.sourceforge.net/testScript.js</uri>\n<code>200 - OK</code>\n"\
			+"<headers><header name=\"last-modified\">Thu, 19 Oct 2006 01:23:03 GMT</header>\n"\
			+"<header name=\"connection\">close</header>\n<header name=\"date\">removed</heade"\
			+"r>\n<header name=\"etag\">&quot;7c046b-f-4536d377&quot;</header>\n<header name=\""\
			+"content-type\">application/x-javascript</header>\n<header name=\"server\">Apach"\
			+"e/1.3.33 (Unix) PHP/4.3.10</header>\n<header name=\"content-length\">15</header>"\
			+"\n<header name=\"accept-ranges\">bytes</header>\n</headers>\n<body>YWxlcnQoJnF1b"\
			+"3Q7aGVsbG8mcXVvdDspOw==\n</body>\n</httpResponse>\n</httpResponses>\n"
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml") #follow link is set to false
		$stdout = STDOUT
		
		#1 request, but two responses, because we had an embedded src to javascript file
		date_str = Regexp.escape("<header name=\"date\">.*?<\/header>")
		actual_http_response_without_date = actual_http_response.string.to_s.sub(/<header name=\"date\">.*20.*?<\/header>/,"<header name=\"date\">removed</header>")
		actual_http_response_without_date = actual_http_response_without_date.to_s.sub(/<header name=\"date\">.*20.*?<\/header>/,"<header name=\"date\">removed</header>")
		assert_equal(expected_http_response,actual_http_response_without_date,"http response not as expected.")
	end
	
	def test_visit_empty_request_path
#redirect input
		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input

		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		expected_http_response = "<code>200 - OK</code>"
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
		
		ok_response = actual_http_response.string.index(expected_http_response)
		
		assert(ok_response,"http response not as expected.")
	end
	
	#input http request and make sure http response is output
	#needs to be commented out for all unit tests as not everybody has a proxy
	#def test_visit_via_proxy_with_auth_tc3
	#	#redirect input
	#	input = StringIO.new("<httpRequests>\n"\
	#		+ "<httpRequest>http://honeyc.sourceforge.net/webBrowserUnitTest.html?dummmyVar1=1&amp;dummyVar2=2</httpRequest>\n"\
	#		+ "</httpRequests>\n") 
	#	$stdin = input
	#
	#	#redirect output
	#	actual_http_response = StringIO.new
	#	$stdout = actual_http_response
	#	expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
	#		+"UnitTest.html?dummmyVar1=1&amp;dummyVar2=2</uri>\n<code>200 - OK</code>\n"\
	#		+"<headers><header name=\"last-modified\">Fri, 06 Oct 2006 04:09:52 GMT</header>\n<header"\
	#		+" name=\"connection\">close</header>\n<header name=\"date\">removed</header>\n<he"\
	#		+"ader name=\"etag\">&quot;7c1245-de-4525d710&quot;</header>\n<header name=\"conte"\
	#		+"nt-type\">text/html</header>\n<header name=\"server\">Apache/1.3.33 (Unix) PHP/4"\
	#		+".3.10</header>\n<header name=\"content-length\">222</header>\n<header name=\"x-p"\
	#		+"ad\">avoid browser bug</header>\n<header name=\"accept-ranges\">bytes</header>\n"\
	#		+"</headers>\n<body>Jmx0O2h0bWwmZ3Q7DQombHQ7aGVhZCZndDsNCiZsdDt0aXRsZSZndDtVbnRp\n"\
	#		+"dGxlZCBEb2N1bWVudCZsdDsvdGl0bGUmZ3Q7DQombHQ7bWV0YSBodHRwLWVx\ndWl2PSZxdW90O0Nvbn"\
	#		+"RlbnQtVHlwZSZxdW90OyBjb250ZW50PSZxdW90O3Rl\neHQvaHRtbDsgY2hhcnNldD1pc28tODg1OS0x"\
	#		+"JnF1b3Q7Jmd0Ow0KJmx0Oy9o\nZWFkJmd0Ow0KDQombHQ7Ym9keSZndDsNClRoaXMgaXMgYSB0ZXN0IH"\
	#		+"BhZ2Ug\nZm9yIHRoZSB3ZWIgYnJvd3NlciB1bml0IHRlc3QucnVsZTJwY3JlDQombHQ7\nL2JvZHkmZ3"\
	#		+"Q7DQombHQ7L2h0bWwmZ3Q7DQo=\n</body>\n</httpResponse>\n</httpResponses>\n"
	#	
	#	webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestProxyAuth.xml")
	#	$stdout = STDOUT
	#
	#	date_str = Regexp.escape("<header name=\"date\">.*?<\/header>")
	#	actual_http_response_without_date = actual_http_response.string.to_s.sub(/<header name=\"date\">.*?<\/header>/,"<header name=\"date\">removed</header>")
	#	assert_equal(expected_http_response,actual_http_response_without_date,"http response not as expected.")
	#end

	#input http request and make sure http response is output
	#needs to be commented out for all unit tests as not everybody has a proxy
	#def test_visit_via_proxy_without_auth_tc4
	#	#redirect input
	#	input = StringIO.new("<httpRequests>\n"\
	#		+ "<httpRequest>http://honeyc.sourceforge.net/webBrowserUnitTest.html?dummmyVar1=1&amp;dummyVar2=2</httpRequest>\n"\
	#		+ "</httpRequests>\n") 
	#	$stdin = input
	#
	#	#redirect output
	#	actual_http_response = StringIO.new
	#	$stdout = actual_http_response
	#	expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
	#		+"UnitTest.html?dummmyVar1=1&amp;dummyVar2=2</uri>\n<code>200 - OK</code>\n"\
	#		+"<headers><header name=\"last-modified\">Fri, 06 Oct 2006 04:09:52 GMT</header>\n<header"\
	#		+" name=\"connection\">close</header>\n<header name=\"date\">removed</header>\n<he"\
	#		+"ader name=\"etag\">&quot;7c1245-de-4525d710&quot;</header>\n<header name=\"conte"\
	#		+"nt-type\">text/html</header>\n<header name=\"server\">Apache/1.3.33 (Unix) PHP/4"\
	#		+".3.10</header>\n<header name=\"content-length\">222</header>\n<header name=\"x-p"\
	#		+"ad\">avoid browser bug</header>\n<header name=\"accept-ranges\">bytes</header>\n"\
	#		+"</headers>\n<body>Jmx0O2h0bWwmZ3Q7DQombHQ7aGVhZCZndDsNCiZsdDt0aXRsZSZndDtVbnRp\n"\
	#		+"dGxlZCBEb2N1bWVudCZsdDsvdGl0bGUmZ3Q7DQombHQ7bWV0YSBodHRwLWVx\ndWl2PSZxdW90O0Nvbn"\
	#		+"RlbnQtVHlwZSZxdW90OyBjb250ZW50PSZxdW90O3Rl\neHQvaHRtbDsgY2hhcnNldD1pc28tODg1OS0x"\
	#		+"JnF1b3Q7Jmd0Ow0KJmx0Oy9o\nZWFkJmd0Ow0KDQombHQ7Ym9keSZndDsNClRoaXMgaXMgYSB0ZXN0IH"\
	#		+"BhZ2Ug\nZm9yIHRoZSB3ZWIgYnJvd3NlciB1bml0IHRlc3QucnVsZTJwY3JlDQombHQ7\nL2JvZHkmZ3"\
	#		+"Q7DQombHQ7L2h0bWwmZ3Q7DQo=\n</body>\n</httpResponse>\n</httpResponses>\n"
	#	
	#	webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestProxy.xml")
	#	$stdout = STDOUT
	#
	#	date_str = Regexp.escape("<header name=\"date\">.*?<\/header>")
	#	actual_http_response_without_date = actual_http_response.string.to_s.sub(/<header name=\"date\">.*?<\/header>/,"<header name=\"date\">removed</header>")
	#	assert_equal(expected_http_response,actual_http_response_without_date,"http response not as expected.")
	#end
	
	def test_visit_dont_follow_link_tc29
		#redirect input
		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net/webBrowserUnitTestAbsoluteLink.html</httpRequest>\n"\
			+ "</httpRequests>\n") #page contains link, but we configure webbrowser to ignore links
		$stdin = input
	
		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"UnitTestAbsoluteLink.html</uri>\n<code>200 - OK</code>\n<headers><header name=\""\
			+"last-modified\">Fri, 06 Oct 2006 04:09:53 GMT</header>\n<header name=\"connectio"\
			+"n\">close</header>\n<header name=\"date\">removed</header>\n<header name=\"etag\""\
			+">&quot;7c054b-13f-4525d711&quot;</header>\n<header name=\"content-type\">text/h"\
			+"tml</header>\n<header name=\"server\">Apache/1.3.33 (Unix) PHP/4.3.10</header>\n"\
			+"<header name=\"content-length\">319</header>\n<header name=\"x-pad\">avoid brows"\
			+"er bug</header>\n<header name=\"accept-ranges\">bytes</header>\n</headers>\n<bod"\
			+"y>Jmx0O2h0bWwmZ3Q7DQombHQ7aGVhZCZndDsNCiZsdDt0aXRsZSZndDtVbnRp\ndGxlZCBEb2N1bWVu"\
			+"dCZsdDsvdGl0bGUmZ3Q7DQombHQ7bWV0YSBodHRwLWVx\ndWl2PSZxdW90O0NvbnRlbnQtVHlwZSZxdW"\
			+"90OyBjb250ZW50PSZxdW90O3Rl\neHQvaHRtbDsgY2hhcnNldD1pc28tODg1OS0xJnF1b3Q7Jmd0Ow0K"\
			+"Jmx0Oy9o\nZWFkJmd0Ow0KDQombHQ7Ym9keSZndDsNClRoaXMgaXMgYSB0ZXN0IHBhZ2Ug\nZm9yIHRo"\
			+"ZSB3ZWIgYnJvd3NlciB1bml0IHRlc3Qgd2l0aCBhIGFic29sdXRl\nIGxpbmsgdG8gJmx0O2EgaHJlZj"\
			+"0mcXVvdDtodHRwOi8vaG9uZXljLnNvdXJj\nZWZvcmdlLm5ldC93ZWJCcm93c2VyVW5pdFRlc3QuaHRt"\
			+"bCZxdW90OyZndDth\nbm90aGVyIHBhZ2UuICZsdDsvYSZndDsNCiZsdDsvYm9keSZndDsNCiZsdDsv\n"\
			+"aHRtbCZndDsNCg==\n</body>\n</httpResponse>\n</httpResponses>\n"
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
	
		#1 response although it included link, because we configured webbrowser not to follow link
		date_str = Regexp.escape("<header name=\"date\">.*?<\/header>")
		actual_http_response_without_date = actual_http_response.string.to_s.sub(/<header name=\"date\">.*?<\/header>/,"<header name=\"date\">removed</header>")
		assert_equal(expected_http_response,actual_http_response_without_date,"http response not as expected.")
	end
	

	
	def test_visit_to_invalid_host_name_tc33
		#redirect input
		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://www.invalid_host_name%d0.com/</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input

		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		
		expected_http_response = "<code>400 - Bad request"
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
		
		error_response = actual_http_response.string.index(expected_http_response)
		
		assert(error_response,"http response not as expected.")
	end

	#test existant server but non existant url
	def test_visit_to_nonexisting_url_tc6
		#redirect input

		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net/idontexist.html</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input
		
		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		
		expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/idontexist.html</uri>\n"\
			+ "<code>404 - Not Found</code>\n"
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
		
		assert(actual_http_response.string.index(expected_http_response),\
			"http response not as expected")
	
	end

	#handling of invalid httpRequest
#	def test_handling_invalid_httprequest_tc7
#		#redirect input
#		input = StringIO.new("<httpRequestseyc.sourceforge.net/idontexist.html</httpRequest>\n"\
#			+ "</httpRequests>\n") 
#		$stdin = input
#
#		#redirect output
#		actual_http_response = StringIO.new
#
#		begin
#			webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
#			assert(false, "NO argument error was raised on invalud httpRequest")
#		rescue ArgumentError
#			#what we want
#		end
#	end
	
	#test non existant server
	def test_visit_image_tc9
		#redirect input
		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net/images/head-banner.jpg</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input

		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		
		expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/images/head-banner.jpg</uri>\n"\
			+ "<code>200 - OK</code>\n<headers>"
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
		
		assert(actual_http_response.string.index(expected_http_response),"http response not as expected.")
	end
	
	#test redirect server
	def test_visit_redirect_tc27
		#redirect input
		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net/webBrowserRedirectUnitTest.php</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input

		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"RedirectUnitTest.php</uri>\n<code>200 - OK</code>\n<headers><header name=\"last-"\
			+"modified\">Fri, 06 Oct 2006 04:09:52 GMT</header>\n<header name=\"connection\">c"\
			+"lose</header>\n<header name=\"date\">removed</header>\n<header name=\"etag\">&qu"\
			+"ot;7c1245-de-4525d710&quot;</header>\n<header name=\"content-type\">text/html</h"\
			+"eader>\n<header name=\"server\">Apache/1.3.33 (Unix) PHP/4.3.10</header>\n<heade"\
			+"r name=\"content-length\">222</header>\n<header name=\"x-pad\">avoid browser bug"\
			+"</header>\n<header name=\"accept-ranges\">bytes</header>\n</headers>\n<body>Jmx0"\
			+"O2h0bWwmZ3Q7DQombHQ7aGVhZCZndDsNCiZsdDt0aXRsZSZndDtVbnRp\ndGxlZCBEb2N1bWVudCZsdD"\
			+"svdGl0bGUmZ3Q7DQombHQ7bWV0YSBodHRwLWVx\ndWl2PSZxdW90O0NvbnRlbnQtVHlwZSZxdW90OyBj"\
			+"b250ZW50PSZxdW90O3Rl\neHQvaHRtbDsgY2hhcnNldD1pc28tODg1OS0xJnF1b3Q7Jmd0Ow0KJmx0Oy"\
			+"9o\nZWFkJmd0Ow0KDQombHQ7Ym9keSZndDsNClRoaXMgaXMgYSB0ZXN0IHBhZ2Ug\nZm9yIHRoZSB3ZW"\
			+"IgYnJvd3NlciB1bml0IHRlc3QucnVsZTJwY3JlDQombHQ7\nL2JvZHkmZ3Q7DQombHQ7L2h0bWwmZ3Q7"\
			+"DQo=\n</body>\n</httpResponse>\n</httpResponses>\n"
								
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
		
		date_str = Regexp.escape("<header name=\"date\">.*?<\/header>")
		actual_http_response_without_date = actual_http_response.string.to_s.sub(/<header name=\"date\">.*?<\/header>/,"<header name=\"date\">removed</header>")
		assert_equal(expected_http_response,actual_http_response_without_date,"http response not as expected.")
	end
	
	#test redirect server
	def test_visit_too_many_redirect_tc28
		#redirect input
		input = StringIO.new("<httpRequests>\n"\
			+ "<httpRequest>http://honeyc.sourceforge.net/webBrowserTooManyRedirectUnitTest.php</httpRequest>\n"\
			+ "</httpRequests>\n") 
		$stdin = input

		#redirect output
		actual_http_response = StringIO.new
		$stdout = actual_http_response
		expected_http_response = "<httpResponses>\n<httpResponse>\n<uri>http://honeyc.sourceforge.net/webBrowser"\
			+"TooManyRedirectUnitTest.php</uri>\n<code>302 - Too many redirects.</code>\n<headers></headers>\n<body></body>\n</httpResponse>\n</httpResponses>\n"
		
		webBrowser = WebBrowser.new("visitor/WebBrowserConfigurationUnitTestDontFollow.xml")
		$stdout = STDOUT
		
		assert_equal(expected_http_response,actual_http_response.string,"http too many redirected response not as expected.")
	end
end

#comment the next two lines out to enable running this unit test by executing
#ruby visitor/WebBrowser.rb
#require 'test/unit/ui/console/testrunner'
#Test::Unit::UI::Console::TestRunner.run(WebBrowserTest)

