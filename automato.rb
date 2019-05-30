#!/usr/bin/env ruby
# automato.rb
# Sanjiv Kawa
# @kawabungah

require './helpers/connector.rb'
require './helpers/cli.rb'
require './helpers/ldap_querier.rb'
require './helpers/smb_querier.rb'

puts "automato v2.1"
puts "Written by: Sanjiv Kawa"
puts "Twitter: @kawabungah"
puts ""

Cli.start(ARGV)
