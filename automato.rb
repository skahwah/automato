#!/usr/bin/env ruby
# automato.rb
# Sanjiv Kawa
# @hackerjiv

require './helpers/connector.rb'
require './helpers/cli.rb'
require './helpers/ldap_querier.rb'
require './helpers/smb_querier.rb'

puts "automato v2.0"
puts "Written by: Sanjiv Kawa"
puts "Twitter: @hackerjiv"
puts ""

Cli.start(ARGV)
