#!/usr/bin/env ruby

# smb_querier.rb
# Sanjiv Kawa
# @hackerjiv

require './helpers/ldap_querier.rb'

def local_admin(smb)
  client = smb[0]
  ip = smb[1]
  path = "\\\\#{ip}\\c$"

  begin
    tree = client.tree_connect(path)
    return "[+] #{client.domain}\\#{client.username} is an administrator on #{ip}"
  rescue StandardError => e
    return "[-] #{client.domain}\\#{client.username} is not an administrator on #{ip}"
  end
end
