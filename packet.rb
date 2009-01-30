#!/usr/bin/env ruby

class Packet
	attr_reader :protocol, :src_ip, :dst_ip, :src_port, :dst_port, :direction
	attr_accessor :interface, :icmptype

	alias via= interface=
	alias via interface

	def initialize params
		self.protocol = :tcp
		self.icmptype = 0
    self.src_port = 0
    self.dst_port = 0
		params.each{ |k,v|
			self.send("#{k}=",v)
		}

		%w'from to'.each{ |param|
			raise "'#{param}' param is not set!" unless self.send(param)
		}

    if protocol != :icmp
      %w'src_port dst_port'.each{ |param|
        puts "[?] packet #{param} is not set! using default value 0" if self.send(param) == 0
      }
    end
	end

  def self.from_string s
    h = {}
    a = s.split
    if %w'ip tcp icmp udp'.include?(a[0])
      h[:protocol] = a.shift.to_sym
    end
    pos = 0
    while word = a[pos]
      pos += 1
      arg1 = a[pos]
      arg2 = a[pos+1]
      case word
        when 'from'
          raise "gimme a FROM addr!" unless arg1
          h[:from] = arg1
          pos += 1
          if arg2 =~ /^\d+$/
            h[:src_port] = arg2.to_i
            pos += 1
          end

        when 'to'
          raise "gimme a TO addr!" unless arg1
          h[:to] = arg1
          pos += 1
          if arg2 =~ /^\d+$/
            h[:dst_port] = arg2.to_i
            pos += 1
          end

        when 'in', 'out'
          h[:direction] = word
      end
    end
    Packet.new h
  end

	def protocol= proto
		raise "Invalid protocol" unless [:tcp, :udp, :icmp].include?(proto)
		@protocol = proto
	end

	def src_ip= ip
		NetAddr::CIDR.create ip # validate ip
		@src_ip = ip
	end
	alias from= src_ip=
	alias from src_ip

	def dst_ip= ip
		NetAddr::CIDR.create ip # validate ip
		@dst_ip = ip
	end
	alias to= dst_ip=
	alias to dst_ip

	def src_port= port
		port = port.to_i
		raise "Invalid port" if port<0 || port>65535
		@src_port = port
	end

	def dst_port= port
		port = port.to_i
		raise "Invalid port" if port<0 || port>65535
		@dst_port = port
	end

  def direction= dir
    dir = dir.downcase.to_sym
    raise "Invalid direction" unless [:in, :out].include?(dir)
    @direction = dir
  end
end
