 require 'test/unit/testsuite'
 require 'test/unit/ui/console/testrunner'
 require 'find'

module Kernel
  def get_class_for_name(name, objects = [Object])
    #STDERR.puts name.to_s
    return nil if objects.size == 0
    object = objects.shift
    object.constants.each do |constant_name|
      real_object = object.const_get(constant_name)
      case real_object
      when Class
	return real_object if constant_name == name
      when Module
	objects << real_object
      end
    end
    return get_class_for_name(name, objects)
  end
end

class UnitTester
   def self.suite
	exceptions = ["HoneyC","UnitTester"]
	suite = Test::Unit::TestSuite.new("HoneyC Unit Tests")
	
   	#find all rb files
	Find.find(".") do |full_file_name|
		if /.rb/ =~ full_file_name and !(/.svn/ =~ full_file_name)
			/.*\// =~ full_file_name
			path = $&[2..$&.length]
			classname = full_file_name[$&.length..-4]
			
			if !exceptions.index(classname)
				#assume test is under classname + "Test"
				#run unit test on them except on the exceptions
				
				require path + classname
				classname.sub!(/\.tab/,"") #silly replacement for the snortruleparser, since this is an automatically generated class.
				unit_test = get_class_for_name(classname + "Test")
				if(unit_test==nil)
					STDERR.puts "No unit test defined for class " + classname + "."
				else
					suite << unit_test.suite	
				end
			end
		end
	end

	return suite
   end
 end
 Test::Unit::UI::Console::TestRunner.run(UnitTester)
