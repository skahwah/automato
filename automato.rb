#!/usr/bin/env ruby

require 'rubygems'
require 'open-uri'
require 'nokogiri' 
require 'optparse'
require 'ostruct'

# This method checks to see if a program exists on the system, credit to mislav on stackoverflow
def which(cmd)
  exts = ENV['PATHEXT'] ? ENV['PATHEXT'].split(';') : ['']
  ENV['PATH'].split(File::PATH_SEPARATOR).each do |path|
    exts.each { |ext|
      exe = File.join(path, "#{cmd}#{ext}")
      return exe if File.executable?(exe) && !File.directory?(exe)
    }
  end
  return nil
end

# This method compliments he which method
def programChecker(cmd)
  if which(cmd).nil?
    abort(red("EXITING: Please install #{cmd} before continuing"))
  end
end

# This method simply displays the title of the program
def title()
  puts gray("automato.rb v1.0")
  puts gray("Written by: Sanjiv Kawa")
  puts gray("Twitter: @skawasec")
end

# This method changes text color to a supplied integer value which correlates to Ruby's color representation
def colorize(text, color_code)
	"\e[#{color_code}m#{text}\e[0m"
end

# This method changes text color to gray
def gray(text)
	colorize(text, 100)
end

# This method changes text color to red
def red(text)
  colorize(text, 101)
end

# This method changes text color to blue
def blue(text)
	colorize(text, 104)
end

# This method will check to see if the domain credentials which have been set are valid.
def creds_check(domain,username,password,dc_ip)
  #silently check if the credentials are still valid
  rpc = `rpcclient -U "#{domain}\\#{username}%#{password}" #{dc_ip} -c enumdomains | head -n 1`
    if rpc.include? "NT_STATUS_LOGON_FAILURE"
      puts ""
      puts red("ALERT! It looks like the credentials that were previously used have expired.")
      puts "The #{domain}\\#{username} account could be locked out. Please change your credentials."
      puts ""
      abort
    end
end

# This method will check to see if the IP address for the remote domain controller is responsive.
def ip_check(dc_ip,enum,*msg) 
  msg = *msg
  if enum.length == 0
    puts ""
    puts red("It looks like the target domain contoller at #{dc_ip} is unresponsive")
    abort
  elsif enum.length == 1
    puts ""
    puts red("It looks like the target domain contoller at #{dc_ip} is unresponsive")
    abort
  elsif msg.nil? == false
    puts enum
    puts ""
    puts blue(msg.join(', '))
  end
end

# This method will enumerate all domain users in the target domain and place them into an output file.
def enum_dom_users(domain,username,password,dc_ip)
  output = "#{domain}-users.txt"
  puts "Currently enumerating all domain users ..."
  enum = `rpcclient -U "#{domain}\\#{username}%#{password}" #{dc_ip} -c enumdomusers | awk -F"[" {'print $2'} | awk -F"]" {'print $1'} | tee #{output}`
  msg = "Success! All domain users have been stored in #{output}"
  ip_check(dc_ip,enum,msg)
end

# This method will enumerate all domain groups in the target domain and place them into an output file.
def enum_dom_groups(domain,username,password,dc_ip)  
  output = "#{domain}-groups.txt"
  puts "Currently enumerating all domain groups ..."
  enum = `rpcclient -U "#{domain}\\#{username}%#{password}" #{dc_ip} -c enumdomgroups | awk -F"[" {'print $2'} | awk -F"]" {'print $1'} | tee #{output}`
  msg = "Success! All domain groups have been stored in #{output}"
  ip_check(dc_ip,enum,msg)
end

# This method will enumerate all users within a specific domain group in the target domain and place them into an output file.
def enum_group_membership(domain,username,password,dc_ip,group)    
  groupFormatted = group.gsub(' ','-')    
  output = "#{domain}-#{groupFormatted}.txt"
  enum = `net rpc group members "#{group}" -I #{dc_ip} -U "#{domain}\\#{username}%#{password}" | tee #{output}`  
  
  if enum.length == 0
    puts ""
    puts red("It looks like the target domain contoller at #{dc_ip} is unresponsive or the group #{group} does not exist")
    abort
  elsif enum.length == 1
    puts ""
    puts red("It looks like the target domain contoller at #{dc_ip} is unresponsive or the group #{group} does not exist")
    abort
  else
    puts enum
    puts ""
    puts blue("Success! Members which are in the #{group} group have been stored in #{output}")
  end
  
end

# This method will grab the attributes for all domain users in the target domain and place them into an output file.
def grab_attr(domain,username,password,dc_ip)  
  cmd = `rpcclient -U '#{domain}\\\\#{username}%#{password}' #{dc_ip} -c lsaquery | head -n 1`
  ip_check(dc_ip,cmd) 
  
  output = "#{domain}-attributes.txt"
  temp_file = "temp1"
  
  cmd = `rpcclient -U '#{domain}\\\\#{username}%#{password}' #{dc_ip} -c enumdomusers | cut -d " " -f 2 | sed 's/rid:\\[//g' | sed 's/\\]//g' > #{temp_file}` 
  
  puts "Looking up user account attrubutes for each user." 
  puts ""  
  
  user_arr = Array.new
  r = File.open(temp_file) 
  r.each_line {|line| user_arr.push line.chomp}
  del_temp = `rm #{temp_file}`
  
  File.open(output, 'w') do |file| 
    user_arr.each do |user| 
      puts "Attributes for RID: #{user}"
      attrib = `rpcclient -U '#{domain}\\\\#{username}%#{password}' #{dc_ip} -c  'queryuser #{user}'`
      puts attrib
      file.write("Attributes for RID: #{user}\n")
      file.write(attrib)  
    end
  end
  puts blue("Success! All users attributes have been stored in #{output}")
end

# This method will check the bad password count for each user in the domain users group and place them into an output file.
def badPw(domain,username,password,dc_ip)
  cmd = `rpcclient -U '#{domain}\\\\#{username}%#{password}' #{dc_ip} -c lsaquery | head -n 1`
  ip_check(dc_ip,cmd) 
    
  output = "#{domain}-bad-password-count.txt"
  temp_file = "temp1"
  
  cmd = `rpcclient -U '#{domain}\\\\#{username}%#{password}' #{dc_ip} -c enumdomusers | cut -d " " -f 2 | sed 's/rid:\\[//g' | sed 's/\\]//g' > #{temp_file}` 
  
  puts "Looking up the bad password count for each user."  
  puts ""  
  
  user_arr = Array.new
  r = File.open(temp_file) 
  r.each_line {|line| user_arr.push line.chomp}
  del_temp = `rm #{temp_file}`
    
  File.open(output, 'w') do |file| 
    user_arr.each {|rid| 
    print "#{rid} ";  
    file.write("#{rid} ");
    cmd = `rpcclient -U '#{domain}\\\\#{username}%#{password}' #{dc_ip} -c 'queryuser #{rid}' | egrep "User|bad" | awk -F":" {'print $2'} | awk -F" " {'print $1'} | awk '{printf "%s ",$0} END {print ""}'`; 
    puts cmd;
    file.write(cmd)}
  end
  puts blue("Success! All bad password counts have been stored in #{output}")
end

=begin
This method will automate a majority of the enumeration tasks such as, obtaining a domain user list, domain group list, domain admins lists, domain computers list
user attributes for the domain, enterprise admins lists, built-in administrators list and place them into an output file.
=end
def all(domain,username,password,dc_ip)

  enum_dom_users(domain,username,password,dc_ip)

  enum_dom_groups(domain,username,password,dc_ip)

  groupArr = ["Domain Admins","Domain Computers","Enterprise Admins","Administrators"]

  groupArr.each {|group| enum_group_membership(domain,username,password,dc_ip,group)}

  grab_attr(domain,username,password,dc_ip) 
end

=begin
This method will conduct a brute force attack against the taget domain using a user supplied list of users and a common password.
The end result is an output file which shows which users have been identified as existing in the domain with the common password.
=end
def domain_user_bf(dc_ip,domain,password,huntDu)
  file = huntDu
  output = "#{domain}-password-attack-#{password}.txt"
  
  user_hash = Hash.new
  
  r = File.open(file) 
  r.each_line {|line| user_hash[line.chomp] = password}
  
  File.open(output, 'w') do |file| 
    user_hash.each do |key, value| 
      current = "Testing: #{key} #{value} "
      puts current
      file.write(current)
      smb = `smbclient -U #{domain}\\\\#{key}%#{value} //#{dc_ip}/NETLOGON -c dir`
      puts smb
      file.write(smb)  
    end
  end
  data_processing = `sed '/failed/d' #{output} > 1; rm #{output}; cat 1 | awk -F" " {'print $2 " " $3'} > 2; rm 1; sed -n '/#{password}/p' 2 > 3; rm 2; echo "The Following Users Exist in Domain: #{domain}" > #{output}; echo " " >> #{output}; cat 3 >> #{output}; rm 3`
  puts ""
  puts blue("Success! All users which are members of the #{domain} domain have been stored in #{output}")
end

=begin
This method will test if a user supplied domain user name and password is a local admin against a range of IP addresses provided in a user supplied input file.
The end result is an output file which shows which users have been identified as a local admin against each IP address in the user supplied file.
=end
def domain_user_local_admin(domain,username,password,huntLa)
  file = huntLa
  output = "#{domain}-local-admin-#{username}.txt"
  
  ip_arr = Array.new
  
  r = File.open(file) 
  r.each_line {|line| ip_arr.push line.chomp}
    
  File.open(output, 'w') do |file| 
      ip_arr.each do |ip| 
        current = "Testing: #{domain}\\#{username} #{password} against #{ip}"
        puts current
        file.write(current)
        smb = `smbclient -U #{domain}\\\\#{username}%#{password} //#{ip}/C$ -c dir`
        puts smb
        file.write(smb)  
      end
  end
  puts ""
  puts blue("Success! Machines that the user #{username} can access as a local administrator are stored in #{output}")
end

# CLI
def cli()
  options = OpenStruct.new
  ARGV << '-h' if ARGV.empty?
  OptionParser.new do |opt|
    opt.banner = "Usage: ruby automato.rb [options]"
    opt.on('Main Arguments:')
    opt.on('-d', '--domain DOMAIN', 'The target domain.') { |o| options.domain = o }
    opt.on('-u', '--username USERNAME', 'A domain user account name.') { |o| options.username = o }    
    opt.on('-p', '--password PASSWORD', 'The password for the corresponding domain user account.') { |o| options.password = o }
    opt.on('-i', '--ip DC_IP', 'The IP address of a domain controller with RPC and LDAP listening.') { |o| options.ip = o }
    opt.on('Options:')
    opt.on('-a', '--all', 'Run a bulk of automato\'s features. Enumerate all domain groups, administrators, computers and user account attributes.') { |o| options.all = o }
    opt.on('-c', '--domain-users', 'Get all domain users in the domain.') { |o| options.du = o }
    opt.on('-g', '--groups', 'Get all domain groups for the domain.') { |o| options.dg = o }
    opt.on('-m', '--member GROUP', 'List all users in a specified domain group. Make sure you escape spaces with a backslash!') { |o| options.group = o }
    opt.on('-t', '--attributes', 'Get the domain account attributes for all domain users.') { |o| options.attrib = o }
    opt.on('-b', '--bad', 'Get the bad password count for all domain users.') { |o| options.bad = o }
    opt.on('-z', '--du-hunter USER_FILE', 'Brute force a list of common usernames with a common password against the target domain.') { |o| options.hdu = o }
    opt.on('-l','--la-hunter IP_FILE', 'Test if a domain user is a local admin against a list of IP addresses with SMB listening in the target domain.') { |o| options.hla = o }
  end.parse!

  dc_ip = options.ip
  domain = options.domain
  username = options.username
  password = options.password
  domUsers = options.du
  domGroups = options.dg
  group = options.group
  attributes = options.attrib
  bad = options.bad
  all = options.all
  huntDu = options.hdu
  huntLa = options.hla
    
  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && domUsers == true
    creds_check(domain,username,password,dc_ip)
    enum_dom_users(domain,username,password,dc_ip)
  end
  
  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && domGroups == true
    creds_check(domain,username,password,dc_ip)
    enum_dom_groups(domain,username,password,dc_ip)
  end

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && group.nil? == false
    creds_check(domain,username,password,dc_ip)
    enum_group_membership(domain,username,password,dc_ip,group)
  end
  
  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && attributes == true
    creds_check(domain,username,password,dc_ip)
    grab_attr(domain,username,password,dc_ip)
  end
  
  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && bad == true
    creds_check(domain,username,password,dc_ip)
    badPw(domain,username,password,dc_ip)
  end
  
  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && all == true
    creds_check(domain,username,password,dc_ip)
    all(domain,username,password,dc_ip)
  end
  
  if dc_ip.nil? == false && domain.nil? == false && password.nil? == false && huntDu.nil? == false
    domain_user_bf(dc_ip,domain,password,huntDu)
  end
 
  if domain.nil? == false && username.nil? == false && password.nil? == false && huntLa.nil? == false
    domain_user_local_admin(domain,username,password,huntLa)
  end
end

# Displays the title of the program
title() 
puts ""

# Running through precheck
progArr = ["smbclient","rpcclient","net", "sed", "awk", "grep", "egrep", "tee", "head", "rm", "cat", "echo"]
progArr.each {|prog| programChecker(prog)}

cli()
