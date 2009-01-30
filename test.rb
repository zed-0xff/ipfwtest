#!/usr/bin/env ruby

require 'ipfw'
require 'pp'

#pp fw

#fw.verbose = true

#fw.rule! 9970, "skipto 9981 tcp from 192.168.113.250 to 62.165.61.10"

# 192.168.241.166.1184 > 62.165.61.10.3128

if ARGV.size > 0
  p = Packet.from_string( ARGV.join(' '))
  fw = IPFW.from_system :verbose => true, :max_table_id => 10
  fw.packet! p
else
  fw = IPFW.from_system :verbose => true, :max_table_id => 10
  fw.packet!(
    :protocol => :icmp,
    :from => '192.168.237.173',
    :to => '192.168.237.174',
    :src_port => 20065,
    :dst_port => 21
  )
end
