module IPFW::RSpecMatchers
  class Pkt
    def initialize(pkt)
      @pkt = pkt
    end

    def matches?(ipfw)
      @ipfw = ipfw
      @result = @ipfw.packet!(@pkt) == expected_result
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
    def initialize(pkt, nat_id)
      @pkt = pkt
      @nat_id = nat_id
    end

    def expected_result
      [:nat, @nat_id]
    end
  end

  def allow pkt
    Allow.new pkt
  end
  alias :pass :allow

  def block pkt
    Block.new pkt
  end

  def nat pkt, nat_id
    Nat.new pkt, nat_id
  end
end
