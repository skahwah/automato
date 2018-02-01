#!/usr/bin/env ruby

# cli.rb
# Sanjiv Kawa
# @kawabungah

require 'rubygems'
require './helpers/ldap_querier.rb'
require 'thor'

class Cli < Thor
  @@ldap = Connect.new.ldap
  @@state = validate_credentials(@@ldap)

  desc "all", "Run the most popular features. (computers, users, groups, priv, attributes)"
  def all
      if @@state == true then run_all(@@ldap) else puts @@state end
  end

  desc "users", "Get all domain users."
  def users
      if @@state == true then domain_users(@@ldap) else puts @@state end
  end

  desc "computers", "Get all domain computers."
  def computers
    if @@state == true then domain_computers(@@ldap) else puts @@state end
  end

  desc "groups", "Get all domain groups."
  def groups()
    if @@state == true then domain_groups(@@ldap) else puts @@state end
  end

  desc "priv", "Recurse through administrative groups and get users from all nested groups."
  def priv()
    if @@state == true then privileged_group_membership(@@ldap) else puts @@state end
  end

  desc "attr", "Get the account attributes for all domain users."
  def attr()
    if @@state == true then attributes(@@ldap) else puts @@state end
  end

  desc "user USER", "Get the group memberships for a supplied USER"
  def user(user)
    if @@state == true then user_group_membership(@@ldap,user) else puts @@state end
  end

  desc "member GROUP", "List all users in a supplied domain GROUP."
  def member(group)
    if @@state == true then group_membership(@@ldap,group) else puts @@state end
  end

  desc "bad", "Get the bad password count for all domain users."
  def bad()
    if @@state == true then bad_password(@@ldap) else puts @@state end
  end

  desc "spray USER_FILE PASSWORD", "Conduct a password spraying attack against the domain using a USER_FILE and common PASSWORD"
  def spray(user_file,password)
      if remote_check(@@ldap.host,@@ldap.port) == true then password_spray(user_file,password) else puts @@ip_state end
  end

  desc "laps", "Get the laps password for systems in the network"
  def laps()
    if @@state == true then laps_password(@@ldap) else puts @@state end
  end

  desc "localadmin DOMAIN USERNAME PASSWORD IP_FILE", "Identify if a user is a local admin against a list of IP's with SMB open"
  def localadmin(domain, username, password, ip_file)
    smb = []
    if File.exist?(ip_file) == true
      File.open(ip_file).each do |ip|
        ip_state = remote_check(ip.chomp, 445)
        if ip_state == true
          client = Connect.new.smb(domain,username,password,ip.chomp)
          la = local_admin(client)
          puts la
          smb.push la
        else
          puts ip_state
          smb.push ip_state
        end
      end
      file = "#{$domain}-#{username}-local-administrator.txt"
      puts "[+] Systems that #{$domain}\\#{username} is a local administrator on have been written to #{file}"
      output_file(file,smb)
    else
      puts "[!] #{ip_file} does not exist"
      exit
    end
  end
end
