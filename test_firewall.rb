#!/usr/bin/env ruby
require 'ipfw'
require 'pp'

fw = IPFW.from_system :verbose => true, :max_table_id => 10

r=fw.packet!("icmp from 62.165.53.130 to 62.165.61.1")
puts "r=#{r.inspect}"
