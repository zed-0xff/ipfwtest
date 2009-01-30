require 'rubygems'
require 'netaddr'

class NetAddr::CIDRv4
	def inspect
		self.desc.sub(/\/32$/,'')
	end
end

class IPFW::Rule
  @@my_ips = [ NetAddr::CIDR.create('127.0.0.1') ]

	def initialize a
		a.shift if a.first == 'log'

		if a.first == 'logamount'
			a.shift
			a.shift
		end

    (proto = a.shift) && self.protocol = proto 

		prev_token = nil
		until a.empty?
			case token=a.shift
				when 'not'
					next_token = a.shift
					if next_token == 'via'
						instance_variable_set "@negate_interface", true
						next_token = a.shift
						self.send "via=", next_token
					else
						raise "Invalid token '#{token}'"
					end
				when 'from', 'to', 'via', 'src-port', 'dst-port', 'icmptypes'
					next_token = a.shift
					if next_token == 'not'
						next_token = a.shift
						instance_variable_set "@negate_#{token.gsub('-','_')}", true
					end
					self.send "#{token.gsub('-','_')}=", next_token
				when /^\d+/
					if %w'from to'.include?prev_token
						send "#{prev_token}_port=", token
					else
						raise "Invalid token '#{token}'"
					end
				when '//'
					@comment = a.join(' ')
					a=[]
        when 'in', 'out'
          self.direction = token
				when *%w'established setup keep-state'
					# ignore
				when *%w'iptos'
					# ignore with 1 arg
					a.shift
				when *%w'limit'
					# ignore with 2 args
					a.shift
					a.shift
				else
					raise "Invalid token '#{token}'"
			end
			prev_token = token
		end
	end

	def self.my_ips= ips
		@@my_ips = ips.map{ |ip| NetAddr::CIDR.create(ip) }
	end

	def self.parse rule
		a = rule.downcase.split
		token = a.shift
		if token == 'prob'
			a.shift # skip prob param
			token = a.shift
		end

		case token
			when *%w'allow deny count skipto fwd divert queue pipe nat check-state'
				eval(token.tr('-','_').capitalize).new(a)
			else
				raise "Invalid token '#{token}'"
		end
	end

	def self.parse_addrs addrs
		if addrs.to_s == 'any'
			addrs.to_s.to_sym
		elsif addrs.to_s == 'me'
			@@my_ips
		else
			addrs.split(',').map{ |addr| NetAddr::CIDR.create(addr) }
		end
	end

	def self.parse_ports ports
		ports.split(',').map{ |port|
			port.strip!
			if port =~ /^\d+-\d+$/
				p = port.split('-')
				p[0].to_i..p[1].to_i
			else
				raise "Invalid port '#{port}'" unless port =~ /^\d+$/
				port = port.to_i
				raise "Invalid port '#{port}'" if port<0 || port>65535
				port
			end
		}
	end

	def packet! pkt
		if match?(pkt, false, firewall ? firewall.tables : {})
			action!
		else
			false
		end
	end

	# check if packet matches rule
	def match? pkt, verbose = false, tables = {}
		if verbose
			s = ''

			s << (match_interface?( pkt.interface ) ? 'I' : 'i' )
			s << (match_protocol?( pkt.protocol ) ? 'P' : 'p' )
			s << (match_from?( pkt.from, tables ) ? 'F' : 'f' )
			s << (match_to?( pkt.to, tables ) ? 'T' : 't' )
			s << (match_src_port?( pkt.src_port ) ? 'S' : 's' )
			s << (match_dst_port?( pkt.dst_port ) ? 'D' : 'd' )
			print "#{s}\t"
		end
		match_interface?( pkt.interface ) &&
		match_protocol?( pkt.protocol ) &&
		match_from?( pkt.from, tables ) &&
		match_to?( pkt.to, tables ) &&
		match_src_port?( pkt.src_port ) &&
		match_dst_port?( pkt.dst_port ) &&
		match_icmptype?( pkt.icmptype ) &&
    match_direction?( pkt.direction )
	end

	def match_from? ip, tables={}
		self.negate_from ^ if @from_table
			tables[@from_table.to_i] && tables[@from_table.to_i][ip]
		else
		  self.from == :any || self.from.any?{ |addr| addr.matches?ip }
		end
	end

	def match_to? ip, tables={}
		self.negate_to ^ if @to_table
			tables[@to_table.to_i] && tables[@to_table.to_i][ip]
		else
			self.to == :any || self.to.any?{ |addr| addr.matches?ip }
		end
	end

	def match_interface? i
		!self.interface || ( (self.interface == i) ^ (self.negate_interface) )
	end

	def match_src_port? p
		!self.src_ports || self.src_ports.include?(p) || 
		self.src_ports.any?{ |pr| 
			pr.is_a?(Range) && pr.include?(p)
		}
	end

	def match_dst_port? p
		!self.dst_ports || self.dst_ports.include?(p) || 
		self.dst_ports.any?{ |pr| 
			pr.is_a?(Range) && pr.include?(p)
		}
	end

	def match_protocol? p
		!self.protocol || self.protocol == p || self.protocol == :ip
	end

	def match_icmptype? p
		return true if self.protocol != :icmp
		return @icmptypes.nil? || @icmptypes.include?(p)
	end

  def match_direction? dir
    @direction == dir || !@direction || !dir
  end

#	def inspect
#		"#{self.class}"
#	end

	attr_reader		:protocol, :src_ports, :dst_ports, :from, :to, :direction
	attr_accessor	:debug, :verbose
	attr_accessor	:interface, :number, :negate_from, :negate_to, :negate_interface, :firewall

  def direction= dir
    dir = dir.downcase.to_sym
    raise "Invalid direction #{dir}" unless [:in, :out].include?(dir)
    @direction = dir
  end

	def protocol= proto
		proto = proto.downcase.to_sym
		raise "Invalid protocol '#{proto}'" unless [:ip, :tcp, :udp, :icmp].include?(proto)
		@protocol = proto
	end

	def from= addrs
		if addrs =~ /^table\((\d+)\)$/ 
			@from_table = $1.to_i
		else
			@from = self.class.parse_addrs(addrs)
		end
	end

	def to= addrs
		if addrs =~ /^table\((\d+)\)$/ 
			@to_table = $1.to_i
		else
			@to = self.class.parse_addrs(addrs)
		end
	end

	def via= iface
		self.interface = iface
	end

	def src_port= ports
    @src_ports = self.class.parse_ports(ports)
  end
	alias from_port= src_port=

  def dst_port= ports
    @dst_ports = self.class.parse_ports(ports)
  end

	def icmptypes= types
		@icmptypes = types.is_a?(Array) ? types : types.split(',').map{ |x| x.to_i }
	end

	def action!
		# generic action
		puts "\t#{self.inspect}" if self.debug
	end
end

class IPFW::Rule::Allow < IPFW::Rule
	def action!
		puts "[*] packet is allowed by rule #{@number}" if verbose
		super
    firewall.stop!
    true
		#throw :stop
	end
end

class IPFW::Rule::Deny < IPFW::Rule
	def action!
		puts "[!] packet is denied by rule #{@number}" if verbose
		super
    firewall.stop!
    false
		#throw :stop
	end
end

class IPFW::Rule::Count < IPFW::Rule
	def action!
		puts "[.] packet is counted by rule #{@number}" if verbose
		super
	end
end

class IPFW::Rule::Skipto < IPFW::Rule
	def initialize a
		@skip_to = a.shift.to_i
		super(a)
	end
	def action!
		puts "[.] packet is skipped to rule #{@skip_to} by rule #{@number}" if verbose
		super
		throw :skip_to, @skip_to
	end
end

class IPFW::Rule::Divert < IPFW::Rule
	def initialize a
		@divert_port = a.shift.to_i
		super(a)
	end
	def action!
		puts "[*] packet is diverted to port #{@divert_port} by rule #{@number}" if verbose
		super
		#throw :stop
    firewall.stop!
    [:divert, @divert_port]
	end
end

class IPFW::Rule::Queue < IPFW::Rule
	def initialize a
		@queue = a.shift.to_i
		super(a)
	end
	def action!
		puts "[*] packet passed to queue #{@queue} by rule #{@number}" if verbose
		super
		firewall.stop! if @firewall.one_pass?
    true
	end
end

class IPFW::Rule::Pipe < IPFW::Rule
	def initialize a
		@pipe = a.shift
		super(a)
	end
	def action!
		pipeno = case @pipe
			when 'tablearg'
				IPFW::Table::last_tablearg
			when /^[0-9]+$/
				@pipe.to_i
			else
				raise "Invalid pipe #{@pipe}"
		end
		puts "[*] packet passed to pipe #{pipeno} by rule #{@number}" if verbose
		super
		firewall.stop! if @firewall.one_pass?
    true
	end
end

class IPFW::Rule::Fwd < IPFW::Rule
	def initialize a
		fwd = a.shift.split(',')
		@fwd_to = NetAddr::CIDR.create(fwd[0])
		@fwd_port = fwd[1].to_i if fwd[1]
		super(a)
	end
	def action!
		puts "[*] packet is forwarded to #{@fwd_to}:#{@fwd_port} by rule #{@number}" if verbose
		super
    firewall.stop!
		[:fwd, @fwd_to, @fwd_port]
	end
end

class IPFW::Rule::Nat < IPFW::Rule
	def initialize a
		@nat_id = a.shift.to_i
		super(a)
	end
	def action!
		puts "[*] packet natted to nat #{@nat_id} by rule #{@number}" if verbose
		super
    firewall.stop!
		[:nat, @nat_id]
	end
end

class IPFW::Rule::Check_state < IPFW::Rule
	def initialize a
		self.from = :any
    self.to = :any
		super(a)
	end
	def action!
		puts "[.] packet is checkstated by rule #{@number}" if verbose
		super
	end
end
