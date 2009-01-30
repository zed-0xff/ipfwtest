require 'rubygems'
require 'netaddr'

class IPFW::Table
	def initialize table_data
		@table = {}
    table_data.each do |row|
      ip_with_mask, value = row.strip.split(' ',2)
      @table[ip_with_mask] = [NetAddr::CIDR.create(ip_with_mask), value.to_i]
    end
	end

	def [](ip)
		@@last_tablearg = nil
		@table.each do |k,v|
			if v[0].matches?(ip)
				@@last_tablearg = v[1].to_i
				return v[1]
			end
		end
		nil
	end

  def ips
    @table.values.map{ |v| v.first.ip }
  end

	def self.last_tablearg
		@@last_tablearg
	end
end

