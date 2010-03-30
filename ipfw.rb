require 'packet'

class IPFW
	attr_accessor :verbose, :one_pass
  attr_reader :tables, :last_rule_id

	def initialize rules=nil
		@rules = {}
    @rule_indexes = []
		@one_pass = false
		load_rules(rules) if rules

		@tables = Hash.new{ |h,k| h[k] = {} }
	end

	def load_rules rules
		rules=rules.split("\n") unless rules.is_a?Array
		rules.each do |rule|
      begin
        rule! *rule.split(' ', 2)
      rescue
        puts "[!] error parsing rule: #{rule}"
        raise
      end
		end
	end

	def inspect
		s = []
	#	@rules.each_with_index{ |rule, idx|
	#		s << "#{idx}\t#{rule.inspect}" if rule
		#}
		"#<IPFW\n\t#{s.join("\n\t")}\n>"
	end

	def packet! pkt
		if pkt.is_a?Hash
      pkt = Packet.new(pkt)
		elsif pkt.is_a?String
      pkt = Packet.from_string(pkt)
    end

    pos = 0
    @stopped = false
    last_rule_result = nil

		catch :stop do
      while idx = @rule_indexes[pos] do
				pos += 1
				arule = @rules[idx]
				#next unless arule
				#puts "[.] #{idx}" if self.verbose

        @last_rule_id = idx

				skip_to = catch(:skip_to) do
					arule.each{ |rule|
						rule.verbose = self.verbose
						last_rule_result = rule.packet!(pkt)
            throw :stop if self.stopped?
					}
					nil
				end
				if skip_to
          skip_to = @rule_indexes.find{ |idx| idx >= skip_to }
          pos = @rule_indexes.index skip_to
        end
			end
		end

		last_rule_result
	end

	def rule! rule_id, rule_body
		raise "Invalid rule id '#{rule_id}'" unless rule_id.to_s =~ /^\d+$/
		rule_id = rule_id.to_s.to_i

		rule_body_wo_comment = rule_body.split('//').first
		if rule_body_wo_comment['{'] && rule_body_wo_comment['}']
			# it's a "multirule": ... from any { via rl0 or via rl1 or via rl1 }
			rules_prefix, t = rule_body_wo_comment.split('{',2)
			rules_infix, rules_suffix = t.split('}',2)
			rules_infix.gsub("\t",' ').split(/ or /i).map do |rule_infix|
				rule!( rule_id, [rules_prefix, rule_infix, rules_suffix].join(' ') )
			end
		else
			rule = Rule.parse( rule_body )
			raise "Cannot parse rule \"#{rule_body}\"" if rule.nil?
			rule.number = rule_id
			rule.firewall = self
			@rules[rule_id] ||= []
			@rules[rule_id] << rule
      @rule_indexes << rule_id
		end
    @rule_indexes.uniq!
    @rule_indexes.sort!
	end

  # called from within rules to stop further processing
  def stop!
    @stopped = true
  end

  def stopped?
    @stopped
  end

	def packet_test_match pkt
		pkt = Packet.new(pkt) if pkt.is_a?Hash
		@rules.each_with_index{ |arule, idx|
			next unless arule
			arule.each{ |rule| 
				puts "#{idx}\t #{rule.match?(pkt, @verbose, @tables)}"
			}
		}
		nil
	end

	def my_ips= ips
		Rule.my_ips = ips
	end

	def table! table_id, table_data
		print "[.] fetching table #{table_id}..                        \r"
		@tables[table_id.to_i] = IPFW::Table.new table_data
	end

	def one_pass?
		@one_pass
	end

	def fetch_table! table_id
		table_data = `sudo ipfw table #{table_id} list`
		#next if table_data.empty?
		table_data = table_data.split("\n")
		table! table_id, table_data
	end

	def self.from_system params = {}
    verbose = params[:verbose]
		fw = IPFW.new

    puts "[.] fetching my_ips.." if verbose
    fw.my_ips = `/sbin/ifconfig | grep -w inet | awk '{print $2}'`.split

    puts "[.] fetching rules.." if verbose
		rules = `sudo ipfw list`
    puts "[.] parsing rules.." if verbose
    fw.load_rules rules

		unless params[:lazy_tables]
			puts "[.] fetching tables.." if verbose
			(0..(params[:max_table_id] || 127)).each do |table_id|
				fw.fetch_table! table_id
			end
		end

    puts "[.] init done" if verbose

		fw.one_pass = `/sbin/sysctl -n net.inet.ip.fw.one_pass`.strip.to_i == 1
    fw.verbose = verbose

		fw
	end
end

require 'ipfw/rule'
require 'ipfw/table'
