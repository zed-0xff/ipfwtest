#!/usr/bin/env ruby19
require 'ipfw'
require 'pp'

fw = IPFW.from_system :verbose => true, :max_table_id => 10

#r=fw.packet!("icmp from 62.165.53.130 to 62.165.61.1")
#puts "r=#{r.inspect}"

#r=fw.packet!("tcp from 192.168.250.118 to 192.168.250.18 22")
#puts "r=#{r.inspect}"

r=fw.packet!("tcp from 62.165.61.234 12332 to 19.19.19.19 80")
puts "r=#{r.inspect}"

#r=fw.packet!("tcp from 192.168.250.182 to 62.165.61.21 20 ")
#puts "r=#{r.inspect}"

