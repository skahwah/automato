#!/usr/bin/env ruby

require 'rubygems'
require 'optparse'
require 'ostruct'
require 'yaml'
require 'socket'
require 'open3'

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

# This method compliments the which method
def programChecker(cmd)
  if which(cmd).nil?
    abort("[!] EXITING: Please install #{cmd} before continuing")
  end
end

# This method displays the title of the program
def title()
  puts "automato.rb v1.7"
  puts "Written by: Sanjiv Kawa"
  puts "Twitter: @hackerjiv"
end

# This load in credentials from credentials.yaml
def load_creds()
  yaml_file = "credentials.yaml"
  if File.exist?(yaml_file) == false then return end
  config = YAML.load_file(yaml_file)
	domain = config["config"]["domain"]
  username = config["config"]["username"]
  password = config["config"]["password"]
  dc_ip = config["config"]["domain_controller"]
  #@threads = config["config"]["threads"]
  cred_store = [domain,username,password,dc_ip]
  return cred_store
end

# run a command
def run_cmd(cmd)
  Open3.popen2e(cmd) do |stdin, stdoe, wait_thr|
    return stdoe.read.to_s
  end
end

# write content out to file
def output_file(file_name,content)
  output = File.open(file_name,"w")
  output.write(content)
  output.close
end

# read content from to file
def file_to_arr(file)
  if File.exist?(file) == true
    file_arr = Array.new
    File.open(file).each do |line|
      file_arr.push line.chomp
    end
    return file_arr
  else
    abort("[!] EXITING: #{file} does not exist.")
  end
end

# This method will check to see if the IP address for the remote domain controller is responsive.
def ip_check(dc_ip)
  port = 389
  begin
    s = Socket.tcp(dc_ip, port, connect_timeout: 1)
    s.close()
    return true
  rescue StandardError
    puts "[!] It looks like the target domain contoller at #{dc_ip} is unresponsive"
    abort
  end
end

# This method will check to see if the IP address and port for the remote host is open
def remote_check(host,port)
  begin
    s = Socket.tcp(host, port, connect_timeout: 0.5)
    s.close()
    return true
  rescue StandardError
    return false
  end
end

# This method will check to see if the domain credentials that have been set are valid.
def creds_check(domain,username,password,dc_ip)
  #silently check if the credentials are still valid
  cmd = "net rpc info -U \"#{domain}\\#{username}%#{password}\" -S #{dc_ip}"
  response = run_cmd(cmd)
  if response.include? "NT_STATUS_LOGON_FAILURE"
    puts "[!] It looks like the credentials that were previously used have expired."
    puts "[-] The #{domain}\\#{username} account could be locked out. Please change your credentials.\n"
    abort
  end
end

# This method will enumerate all domain users in the target domain and place them into an output file.
def enum_dom_users(domain,username,password,dc_ip)
  output = "#{domain}-users.txt"
  cmd = "net rpc user -U \"#{domain}\\#{username}%#{password}\" -S #{dc_ip}"
  response = run_cmd(cmd)
  output_file(output,response)
  puts "[+] Success! All domain users have been stored in #{output}"
end

# This method will enumerate all domain groups in the target domain and place them into an output file.
def enum_dom_groups(domain,username,password,dc_ip)
  output = "#{domain}-groups.txt"
  cmd = "net rpc group -U \"#{domain}\\#{username}%#{password}\" -S #{dc_ip}"
  response = run_cmd(cmd)
  output_file(output,response)
  puts "[+] Success! All domain groups have been stored in #{output}"
end

# This method will enumerate all groups that a supplied user is a part of
def user_group_membership(domain,username,password,dc_ip,user)
  output = "#{domain}-#{user}-groups.txt"
  cmd = "net rpc user info \"#{user}\" -U \"#{domain}\\#{username}%#{password}\" -S #{dc_ip}"
  response = run_cmd(cmd)
  if response.include? "Failed to get groups"
    puts response
  else
    output_file(output,response)
    puts "[+] Success! Group memberships for #{user} have been stored in #{output}"
  end
end

# This method will enumerate all users within a specific domain group in the target domain and place them into an output file.
def enum_group_membership(domain,username,password,dc_ip,group)
  group_formatted = group.gsub(' ','-')
  output = "#{domain}-#{group_formatted}.txt"
  cmd = "net rpc group members \"#{group}\" -U \"#{domain}\\#{username}%#{password}\" -S #{dc_ip}"
  response = run_cmd(cmd)
  if response.include? "Couldn"
    puts response
  else
    output_file(output,response)
    puts "[+] Success! Members which are in the #{group} group have been stored in #{output}"
  end
end

# This method will recurse through the DA, EA and Administrators group and search for all other nested groups then dump those users
def priv_groups(domain,username,password,dc_ip)
    group_arr = ["Domain Admins","Administrators"]
    group_arr.each {|group| enum_group_membership(domain,username,password,dc_ip,group)}

    file = "#{domain}-Domain-Admins.txt"
    domain_admins = file_to_arr(file)

    file = "#{domain}-Administrators.txt"
    administrators = file_to_arr(file)

    enum_dom_users(domain,username,password,dc_ip)
    file = "#{domain}-users.txt"
    domain_users = file_to_arr(file)

    enum_dom_groups(domain,username,password,dc_ip)
    file = "#{domain}-groups.txt"
    domain_groups = file_to_arr(file)

    for i in 0 .. administrators.length-1
      current = administrators[i].to_s.split("\\")[1]
      if domain_groups.include? current
        enum_group_membership(domain,username,password,dc_ip,current)
      end
      if domain_users.include? current
        user_group_membership(domain,username,password,dc_ip,current)
      end
    end

    for i in 0 .. domain_admins.length-1
      current = domain_admins[i].to_s.split("\\")[1]
      if domain_groups.include? current
        enum_group_membership(domain,username,password,dc_ip,current)
      end
      if domain_users.include? current
        user_group_membership(domain,username,password,dc_ip,current)
      end
    end
end

# This method will grab the attributes for all domain users in the target domain and place them into an output file.
def grab_attr(domain,username,password,dc_ip)
  file_name = "#{domain}-attributes.txt"

  enum_dom_users(domain,username,password,dc_ip)
  file = "#{domain}-users.txt"
  domain_users = file_to_arr(file)

  puts "[+] Currently enumerating the attributes for all users in the #{domain} domain"

  output = File.open(file_name,"a")

  for i in 0 .. domain_users.length-1
    cmd = "rpcclient -U \"#{domain}\\#{username}%#{password}\" #{dc_ip} -c \'queryuser #{domain_users[i]}\'"
    response = run_cmd(cmd)
    output.write(response)

    math = i.to_f/(domain_users.length-1)*100
    print "#{math.round(2)}% " if math.to_i % 10==0
  end
  output.close
  puts "\n[+] Success! The attributes for all users has been stored in #{file_name}"
end

# This method will check the bad password count for each user in the domain users group and place them into an output file.
def bad_pw(domain,username,password,dc_ip)
  grab_attr(domain,username,password,dc_ip)
  file = "#{domain}-attributes.txt"
  attributes = file_to_arr(file)
  count_arr = []
  for i in 0 .. attributes.length-1
    if attributes[i].include? "User Name"
      count_arr.push "#{attributes[i].split(":")[1].gsub(/\s+/, "")}"
    end
    if attributes[i].include? "bad_password_count"
      count_arr.push "#{attributes[i].split(":")[1].gsub(/\s+/, "")}"
    end
  end
  file_name = "#{domain}-bad-password-count.txt"
  output = File.open(file_name,"a")
  count_arr.each_slice(2) {|current| output.write(current.join(', ')+"\n")}
  output.close
  puts "[+] Success! The bad password count for all users has been stored in #{file_name}"
end

=begin
This method will automate a majority of the enumeration tasks such as, obtaining a domain user list, domain group list, domain admins lists, domain computers list
user attributes for the domain, enterprise admins lists, built-in administrators list and place them into an output file.
=end
def all(domain,username,password,dc_ip)
  enum_dom_users(domain,username,password,dc_ip)

  enum_dom_groups(domain,username,password,dc_ip)

  enum_group_membership(domain,username,password,dc_ip,"Domain Computers")

  priv_groups(domain,username,password,dc_ip)

  grab_attr(domain,username,password,dc_ip)
end

=begin
This method will conduct a brute force attack against the taget domain using a user supplied list of users and a common password.
The end result is an output file which shows which users have been identified as existing in the domain with the common password.
=end
def domain_user_bf(dc_ip,domain,password,huntDu)
  output = "#{domain}-password-attack-#{password}.txt"
  user_arr = file_to_arr(huntDu)
  for i in 0 .. user_arr.length-1
    cmd = "smbclient -U \"#{domain}\\#{user_arr[i]}%#{password}\" //#{dc_ip}/NETLOGON -c dir"
    cred = "#{domain}\\#{user_arr[i]} #{password}"
    response = run_cmd(cmd)
    if response.include? "Domain="
      puts "[+] #{cred}"
      output_file(output,cred)
    else
      puts "[-] #{cred}"
    end
  end
  puts "\n[+] Success! Results for password spraying the #{domain} domain have been stored in #{output}"
end

=begin
This method will connect to a list of remote IP addresses over SMB and enumerate the local administrators
=end
def local_admin(domain,username,password,local_admin)
  ip_arr = file_to_arr(local_admin)
  for i in 0 .. ip_arr.length-1
    if remote_check(ip_arr[i],445) == true
      output = "#{domain}-#{ip_arr[i].chomp}.txt"
      cmd = "net rpc group members Administrators -U \"#{domain}\\#{username}%#{password}\" -S #{ip_arr[i]}"
      response = run_cmd(cmd)
      puts "[+] Success! Local admins have been stored in #{output}"
      puts response
      output_file(output,response)
    else
      puts "[!] Unable to connect to #{ip_arr[i]}"
    end
  end
end

# CLI
def cli()
  options = OpenStruct.new
  ARGV << '-h' if ARGV.empty?
  OptionParser.new do |opt|
    opt.banner = "Usage: ruby automato.rb [options]"
    opt.on('Authenticated Domain Enumeration:')
    opt.on('-a', '--all', 'Run a bulk of automato\'s features. Enumerate all domain groups, administrators, computers and user account attributes.') { |o| options.all = o }
    opt.on('-d', '--domain-users', 'Get all domain users in the domain.') { |o| options.du = o }
    opt.on('-g', '--groups', 'Get all domain groups for the domain.') { |o| options.dg = o }
    opt.on('-m', '--member GROUP', 'List all users in a specified domain group. ') { |o| options.group = o }
    opt.on('-p', '--priv', 'Recurse through the Administrator and DA groups then dump users from all nested groups.') { |o| options.priv = o }
    opt.on('-u', '--user USER', 'List all groups that a supplied user is a member of.') { |o| options.user = o }
    opt.on('-t', '--attributes', 'Get the domain account attributes for all domain users.') { |o| options.attrib = o }
    opt.on('Additional Features:')
    opt.on('-b', '--bad', 'Get the bad password count for all domain users.') { |o| options.bad = o }
    opt.on('-l', '--local IP_FILE', 'List members who are local administrators on a remote host. (Requires a list of ip addresses with SMB open.)') { |o| options.la = o }
    opt.on('-z', '--du-hunter USER_FILE', 'Password spraying attack. (Requires a list of usernames and a common password.)') { |o| options.hdu = o }
  end.parse!

  domUsers = options.du
  domGroups = options.dg
  group = options.group
  user = options.user
  priv = options.priv
  attributes = options.attrib
  bad = options.bad
  all = options.all
  huntDu = options.hdu
  local_admin = options.la
  domain,username,password,dc_ip = load_creds()

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && domUsers == true
    ip_check(dc_ip)
    creds_check(domain,username,password,dc_ip)
    enum_dom_users(domain,username,password,dc_ip)
  end

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && domGroups == true
    ip_check(dc_ip)
    creds_check(domain,username,password,dc_ip)
    enum_dom_groups(domain,username,password,dc_ip)
  end

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && group.nil? == false
    ip_check(dc_ip)
    creds_check(domain,username,password,dc_ip)
    enum_group_membership(domain,username,password,dc_ip,group)
  end

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && user.nil? == false
    ip_check(dc_ip)
    creds_check(domain,username,password,dc_ip)
    user_group_membership(domain,username,password,dc_ip,user)
  end

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && priv.nil? == false
    ip_check(dc_ip)
    creds_check(domain,username,password,dc_ip)
    priv_groups(domain,username,password,dc_ip)
  end

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && attributes == true
    ip_check(dc_ip)
    creds_check(domain,username,password,dc_ip)
    grab_attr(domain,username,password,dc_ip)
  end

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && bad == true
    ip_check(dc_ip)
    creds_check(domain,username,password,dc_ip)
    bad_pw(domain,username,password,dc_ip)
  end

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && all == true
    ip_check(dc_ip)
    creds_check(domain,username,password,dc_ip)
    all(domain,username,password,dc_ip)
  end

  if dc_ip.nil? == false && domain.nil? == false && username.nil? == false && password.nil? == false && local_admin.nil? == false
    ip_check(dc_ip)
    creds_check(domain,username,password,dc_ip)
    local_admin(domain,username,password,local_admin)
  end

  if dc_ip.nil? == false && domain.nil? == false && password.nil? == false && huntDu.nil? == false
    domain_user_bf(dc_ip,domain,password,huntDu)
  end
end

# Displays the title of the program
title()
puts ""

# Running through precheck
progArr = ["smbclient","rpcclient","net"]
progArr.each {|prog| programChecker(prog)}

cli()
