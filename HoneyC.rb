#!/usr/bin/env ruby

# Main of the honeyC framework. It instanciates the objects in the configuration file and
# glues them together so information flow between components is established.
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require "HoneyCConfiguration"

#public static void main?
if ARGV.length==1 and ARGV[0]=="--help"
	STDERR.puts "Usage: ruby -s HoneyC.rb -c=[location of HoneyC configuration file]"
	STDERR.puts "Starts the honeyC framework based on the options in the configuration file."
	STDERR.puts ""
	STDERR.puts "HoneyC Configuration File Format"
	STDERR.puts "--------------------------------"
	STDERR.puts "<honeyCConfiguration xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
	STDERR.puts " xsi:noNamespaceSchemaLocation=\"HoneyCConfiguration_v1_0.xsd\">"
	STDERR.puts "    <queuer>ruby -s queuer/YahooSearch.rb -c=queuer/qconfig.xml</queuer>"
    	STDERR.puts "    <visitor>java -jar browser.jar -c wb.config</visitor>"
   	STDERR.puts "    <analysisEngine>analysisEngine -c analysisEngine/sn.xml</analysisEngine>"
    	STDERR.puts "</honeyCConfiguration>"
	STDERR.puts ""
	STDERR.puts "The HoneyC Configuration file specifies the queuer, visitor, and analysisEngine"
	STDERR.puts "that should be used for the instance of HoneyC. The values of each of these "
	STDERR.puts "should be the command line command to start the component module independently."
	STDERR.puts "HoneyC will instanciate the component modules and establish the appropriate"
	STDERR.puts "command line redirections. Note that there is not limitation to what the "
	STDERR.puts "component module can be as long as it adheres to the format of the serialized"
	STDERR.puts "object that is passed between the components."
	STDERR.puts ""
	STDERR.puts "Report bugs to <http://sourceforge.net/tracker/?group_id=172208&atid=860868>"
elsif $c == nil
	STDERR.puts "Usage: ruby -s HoneyC.rb -c=[location of HoneyC configuration file]"
	STDERR.puts "Try 'ruby HoneyC.rb --help' for more information."
else
    	conf = HoneyCConfiguration.new($c)
	
	#call queuer | visitor | analysisEngine
	systemCall = conf.queuer+" | "+conf.visitor+" | "+conf.analysis_engine
	#puts systemCall
	system systemCall
end


