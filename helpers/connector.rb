#!/usr/bin/env ruby

# connector.rb
# Sanjiv Kawa
# @kawabungah

require 'rubygems'
require 'net/ldap'
require 'ruby_smb'
require 'socket'
require 'yaml'

# open up credentials.yaml and set a bunch of instance variables
class Credentials
  attr_accessor :domain, :dn_base, :username, :password, :ip, :credentials

  def initialize
    yaml_file = "./credentials.yaml"
    if File.exist?(yaml_file) == false then return end
    config = YAML.load_file(yaml_file)
    @domain = config["config"]["domain"]
    @dn_base = config["config"]["dn_base"]
    @username = config["config"]["username"]
    @password = config["config"]["password"]
    @ip = config["config"]["domain_controller"]
    @credentials = "#{domain}\\#{username}"
  end
end

# the main ldap constructer is built here, there is also a spray method for password spraying attacks
class Connect
  def initialize
    @creds = Credentials.new
  end

  def ldap
    @@ldap = Net::LDAP.new  :host => @creds.ip,
    :port => "389",
    :base => @creds.dn_base,
    :auth => {
      :method => :simple,
      :username => @creds.credentials,
      :password => @creds.password
    }
    return @@ldap
  end

  def ldaps
    @@ldap = Net::LDAP.new  :host => @creds.ip,
    :port => "636",
    :encryption => {
        :method => :simple_tls,
        :tls_options => { :verify_mode => OpenSSL::SSL::VERIFY_NONE }
    },
    :base => @creds.dn_base,
    :auth => {
      :method => :simple,
      :username => @creds.credentials,
      :password => @creds.password
    }
    return @@ldap
  end

  # smb client creator
  def smb(domain, username, password, ip)
    sock = TCPSocket.new ip, 445
    dispatcher = RubySMB::Dispatcher::Socket.new(sock)

    begin
      client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true, domain: domain, username: username, password: password)
      protocol = client.negotiate
      status = client.authenticate
    rescue RubySMB::Error::NetBiosSessionService => e
      puts "[!] Connection failed! Target at #{ip}:445 is SMBv3"
    end
    return client, ip
  end

  # LDAP password spray connector
  def spray(username,password)
    @username = username
    @password = password

    @@ldap = Net::LDAP.new  :host => @creds.ip,
    :port => "389",
    :base => @creds.dn_base,
    :auth => {
      :method => :simple,
      :username => @creds.domain + "\\" + @username,
      :password => @password
    }
  end
end
