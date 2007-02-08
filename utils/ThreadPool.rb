require 'thread'

# A simple thread pool class from:
# Ruby Cookbook, O'Reilly, ISBN 13: 9780596523695
# Authors: Lucas Carlson, Leonard Richardson
# Copyright: O'Reilly Media, Inc., 2006
# 
class ThreadPool
  def initialize(max_size)
    @pool = []
    @max_size = max_size
    @pool_mutex = Mutex.new
    @pool_cv = ConditionVariable.new  
  end
#---
  def dispatch(*args)    
    Thread.new do
      # Wait for space in the pool.
      @pool_mutex.synchronize do
        while @pool.size >= @max_size          
	  STDERR.puts "Pool is full; waiting to run #{args.join(',')}...\n" if $DEBUG
          # Sleep until some other thread calls @pool_cv.signal.
          @pool_cv.wait(@pool_mutex)
        end
      end
#---
      @pool << Thread.current
      begin
        yield(*args)
      rescue => e
        exception(self, e, *args)
      ensure
        @pool_mutex.synchronize do
          # Remove the thread from the pool.
          @pool.delete(Thread.current)
          # Signal the next waiting thread that there's a space in the pool.
          @pool_cv.signal            
        end
      end
    end
  end

  def empty?
  	empty = false
	#@pool_mutex.synchronize {
  	   empty = @pool.empty?
	 #  }
	   return empty
  end
  
  def shutdown
    @pool_mutex.synchronize { @pool_cv.wait(@pool_mutex) until @pool.empty? }
  end

  def exception(thread, exception, *original_args)
    # Subclass this method to handle an exception within a thread.
    STDERR.puts "Exception in thread #{thread}: #{exception}"
  end  
end

#!/usr/bin/env ruby

# Class ThreadPoolTest is a simple unit test of ThreadPool
# Author: Christian Seifert
# http://www.mcs.vuw.ac.nz/~cseifert/blog/index.php

require 'test/unit/testcase'


class ThreadPoolTest < Test::Unit::TestCase
	def test_dummy
		#no unit test for this one...
	end
end
