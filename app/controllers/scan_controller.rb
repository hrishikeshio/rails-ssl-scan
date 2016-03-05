require 'nmap/program'
require 'nmap/xml'
require 'digest/md5'

class ScanController < ApplicationController
	def index
		
	end
	def create
	filename=Digest::MD5.hexdigest(params[:q])+".xml"
	Nmap::Program.scan do |nmap|
	  nmap.syn_scan = false
	  nmap.service_scan = true
	  nmap.os_fingerprint = false
	  nmap.xml = filename
	  nmap.verbose = true
	  nmap.script = 'ssl-poodle, ssl-heartbleed, ssl-ccs-injection, ssl-dh-params'
	  nmap.script_params = 'vulns.showall'
	  nmap.ports = [443]
	  nmap.targets = params[:q]
	end
	
	Nmap::XML.new(filename) do |xml|
	@results=Array.new
	@pos_score=0.0
	@neg_score=0.0
	@total_score=0.0

  xml.each_host do |host|
  	#puts "loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooool"
  #  puts "[#{host.ip}]"
    @hostr=host
    host.scripts.each do |name,output|
   #   output.each_line { |line| puts "  #{line}" }
    end
#puts "booooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooob"
   
    host.each_port do |port|
      puts "  [#{port.number}/#{port.protocol}]"
      result_names=Array.new

      port.scripts.each do |name,output|
        puts "    [#{name}]"
        if name=="http-server-header"
        	result_names.push("[HTTP Server Header]")
        elsif name == "ssl-ccs-injection"
        	result_names.push("[SSL CSS Injection Vulnerability]")
    	elsif name == "ssl-heartbleed"
        	result_names.push("[Heartbleed Vulnerability]")
    	elsif name == "ssl-poodle"
        	result_names.push("[Poodle Vulnerability]")
        elsif name == "ssl-dh-params"
        	result_names.push("[DH Parameters]")
        else
	        headline="["+name+"]"
	        result_names.push(headline)
	    end
        output.each_line do |line|
			puts "      #{line}" 
			result_names.push(line)
			if line.include? "State: NOT VULNERABLE" 
				@pos_score+=1
			elsif line.include? "State: VULNERABLE" 
				@neg_score+=1
			end
		end			
      	end
      @results.push(result_names)
      @total_score=@pos_score/(@pos_score+@neg_score)*100.0
    end
  end
end
		end
end
