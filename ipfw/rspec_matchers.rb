module IPFW::RSpecMatchers
  class Pkt
    def initialize(pkt)
      @pkt = pkt
    end

    def matches?(ipfw)
      @ipfw = ipfw
      (@result = @ipfw.packet!(@pkt)) == expected_result
    end

    def failure_message
      "expected #{expected_result.inspect}, got #{@result.inspect} from rule #{@ipfw.last_rule_id}"
    end

    def negative_failure_message
      "expected NOT #{expected_result.inspect}, got #{@result.inspect} from rule #{@ipfw.last_rule_id}"
    end
  end

  class Allow < Pkt
    def expected_result
      true
    end
  end

  class Block < Pkt
    def expected_result
      false
    end
  end

  class Nat < Pkt
    def initialize(pkt, nat_id=nil)
      @pkt = pkt
      @nat_id = nat_id
    end

    def expected_result
      @nat_id ? [:nat, @nat_id] : [:nat]
    end

    def matches?(ipfw)
      @ipfw = ipfw
			@result = @ipfw.packet!(@pkt)
			if @nat_id
				@result == expected_result
			else
				# nat without nat_id specified (i.e. ANY nat_id)
				@result.is_a?(Array) && @result.first == :nat
			end
    end
  end

  def allow pkt
    Allow.new pkt
  end
  alias :pass :allow

  def block pkt
    Block.new pkt
  end

  def nat pkt, nat_id=nil
    Nat.new pkt, nat_id
  end
end
