#!/usr/bin/env ruby

# Class LinkExtracter is a simple parser that extracts links from a file
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

class LinkExtracter

	#initializer that will parse the configuration file that was passed in
	#and makes it available via the instance variables
	def initialize(file_location)
		@links = Array.new
		
		IO.foreach(file_location) {|line|
			match_uri = /((((http):\/\/)|(www\.))([\w\.]+)([,:%\#&\/?=\w+\.-]+))/
			match_uri =~ line
			
			puts $&.to_s if $& != nil
		}
		
		#todo
		#url decode
		#remove dups
		#polish for xml use
		#wrap into uri tags
		#add configuration header and footer
	end

end

#public static void main?
if ARGV.length==1 and ARGV[0]=="--help"
	STDERR.puts "Usage: ruby -s queuer/LinkExtracter.rb -i=[location of file that contains links]"
	STDERR.puts "Extracts a list of http links from a text file."
	STDERR.puts "It currently extracts only http links without special characters"
	STDERR.puts ""
	STDERR.puts "Report bugs to <https://bugs.honeynet.org/enter_bug.cgi?product=Honey-C>"
elsif $i == nil
	STDERR.puts "Usage: ruby -s queuer/LinkExtracter.rb -i=[location of file that contains links]"
	STDERR.puts "Try 'ruby queuer/LinkExtracter.rb --help' for more information."
else
	search = LinkExtracter.new($i)
end

#!/usr/bin/env ruby

# Class LinkExtracterTest is a simple unit test of LinkExtracter
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'
require 'stringio'

class LinkExtracterTest < Test::Unit::TestCase

	def test_extract_links
		#redirect std out
		actual_links = StringIO.new
		$stdout = actual_links
		
		
		linkExtracter = LinkExtracter.new("queuer/LinkExtracterUnitTest.txt")

		links = String.new
		links.concat "http://www.unit.com\n"
		links.concat "http://www.unittest88.com/index.html?sometest=one%20and%20two&otherparam=2\n"
		links.concat "http://192.168.74.3/test/\n"
		
		
		assert_equal(links.to_s,actual_links.string,"links not as expected.")
		
		$stdout = STDOUT
	end
end

#comment the next two lines out to enable running this unit test by executing
# ruby queuer/LinkExtracter.rb
#require 'test/unit/UI/Console/TestRunner'
#Test::Unit::UI::Console::TestRunner.run(LinkExtracterTest)
