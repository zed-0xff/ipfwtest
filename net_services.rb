class NetServices
	@ports2names={}
	@names2ports={}

	class << self
		def prepare
			ready? || parse_services
		end

		def parse_services params={}
			fname = params[:services] || '/etc/services'
			data = File.read fname
			data.each_line do |line|
				s= parse_service_line line
				next unless s
				@ports2names[ s[:port] ] = s[:names]
				s[:names].each do |name|
					@names2ports[ name  ] = s[:port]
				end
			end
		end

		def ready?
			!@ports2names.empty? && !@names2ports.empty?
		end

		def name2port name
			@names2ports[ name.to_s ]
		end
		alias :n2p :name2port

		def port2name port
			r = @ports2names[ port.to_i ]
			r ? r.first : nil
		end
		alias :p2n :port2name

		def port2names port
			@ports2names[ port.to_i ]
		end
		alias :p2ns :port2names

		private

		def parse_service_line line
			line,comment = line.split('#',2)
			line.strip!
			return nil if line.empty?
			a = line.split(/\s+/)
			return nil if a.size < 2
			t = a[1].split('/')
			h = {
				:name 	 => a[0],
				:names 	 => [a[0]],
				:port 	 => t[0].to_i,
				:proto	 => t[1],
				:comment => comment
			}
			h[:names] += a[2..-1] if a.size > 2
			h
		end
	end
end

if $0 == __FILE__
	# run some tests
	p ["ready?", NetServices.ready?]
	NetServices.parse_services
	p ["ready?", NetServices.ready?]
	p NetServices.p2ns(80)
	p NetServices.p2n(80)
	p NetServices.p2n(0)
	p NetServices.p2n(:zz)
	p NetServices.n2p('www')
	p NetServices.n2p('http')
	p NetServices.n2p('ht22tp')
end

