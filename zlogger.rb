require 'logger'
class ZLogger < Logger
  def initialize(hint = {})
    super(hint[:file] || STDOUT)

    self.formatter = Formatter.new
    self.formatter.datetime_format = hint[:date_format] || "%d.%m %H:%M:%S:"
  end

  def dot
    if @logdev.dev == STDOUT
      formatter.instance_variable_set('@wasdot', true)
      putc '.'
      if !@lastflush || (Time.now-@lastflush) >= 0.2
        STDOUT.flush
        @lastflush = Time.now
      end
    end
  end

	def colorize! h
		self.formatter.colorize!(h)
	end

  # string to prepend to all lines
  def prepend= s
    self.formatter.prepend = s
  end

  class Formatter < Logger::Formatter
    attr_accessor :prepend
    attr_accessor :colorizers

		VALID_COLORS = %w'red green magenta yellow blue'

		def green(text); color(text, "\e[32m"); end
		def red(text); color(text, "\e[31m"); end
		def magenta(text); color(text, "\e[35m"); end
		def yellow(text); color(text, "\e[33m"); end
		def blue(text); color(text, "\e[34m"); end

		def colorize! h
			h.each do |hint,color|
				raise "Invalid color: #{color.inspect}" unless VALID_COLORS.include?(color.to_s)
				self.colorizers ||= {}
				self.colorizers[hint] = color
			end
		end

		def color(text, color_code)
			STDOUT.tty? ? "#{color_code}#{text}\e[0m" : text
		end

    def call(severity, time, progname, msg)
      self.prepend.to_s +
      if severity == 'INFO' && msg.nil?
        @wasdot = false
        # use this if you want a simple blank line without date in your logs:
        # just call a logger.info without any params // zzz :)
        "\n"
      else
        pre = case severity
          when 'WARN'
            '[?]'
          when 'ERROR', 'FATAL'
            '[!]'
          when 'DEBUG'
            '[d]'
          else
            '[.]'
        end
        pre = "\n#{pre}" if @wasdot
        @wasdot = false
        t = format_datetime(time)
        r = pre << (t == '' ? '' : " #{t}") << " " <<  msg2str(msg) << "\n"
				if colorizers
					colorizers.each do |hint,color|
						if r[hint]
							r = self.send(color, r)
							break
						end
					end
				end
				r
      end
    end  
  end
end
