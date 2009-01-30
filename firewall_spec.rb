#!/usr/bin/env ruby
require 'ipfw'
require 'rubygems'
#require 'rspec'
require 'pp'
require 'ipfw/rspec_matchers'

NAT_IF_TTK = 'xl0'
NAT_ID_TTK = 100

$fw = IPFW.from_system :max_table_id => 10
#$fw.verbose = true

$sample_user_white_ips = []
$sample_user_gray_ips = []
$fw.tables[1].ips.sort_by{ rand }.each do |ip|
  if ip['62.165.']
    $sample_user_white_ips << ip 
    break if $sample_user_white_ips.size == 2
  end
end
$fw.tables[1].ips.sort_by{ rand }.each do |ip|
  if ip['192.168.']
    $sample_user_gray_ips << ip 
    break if $sample_user_gray_ips.size == 2
  end
end

$sample_user_ips = $sample_user_gray_ips + $sample_user_white_ips

$netping_ips = %w'192.168.250.198 192.168.251.178 192.168.127.254'
$lightcom_ips = %w'192.168.254.112 192.168.251.206'

$disabled_ips = %w'192.168.55.55 192.168.76.67 62.165.61.255'

def inet_ip
  '194.87.0.50'
end

def random_port
    1000+rand(60000)
end

def free_ip
  '62.165.61.19'
end

def should_pass pkts
  pkts.each do |pkt|
    it "should PASS:\t#{pkt}" do
      @fw.should pass(pkt)
    end
  end
end

def should_block pkts
  pkts.each do |pkt|
    it "should BLOCK:\t#{pkt}" do
      @fw.should block(pkt)
    end
  end
end

describe 'Firewall' do
  include IPFW::RSpecMatchers

  before :all do
    @fw = $fw
  end

  describe "ME -> INET" do
    pkts = []
    pkts << "icmp from 62.165.53.130 to #{inet_ip} out"
    pkts << "tcp from 62.165.53.130 #{random_port} to #{inet_ip} 80 out"
    pkts << "udp from 62.165.53.130 #{random_port} to #{inet_ip} 53 out"
    pkts << "icmp from 62.165.61.1 to #{inet_ip} out"
    pkts << "tcp from 62.165.61.1 #{random_port} to #{inet_ip} 80 out"
    pkts << "udp from 62.165.61.1 #{random_port} to #{inet_ip} 53 out"
    pkts << "udp from 62.165.61.1 #{random_port} to #{inet_ip} 20 out"
    pkts << "udp from 62.165.61.1 #{random_port} to #{inet_ip} 21 out"
    pkts << "udp from 62.165.61.1 #{random_port} to #{inet_ip} 22 out"
    should_pass pkts
  end

#  it "should pass ICMP from www.ru to me" do
#    @fw.packet!("icmp from #{inet_ip} to 62.165.53.130").should == true
#  end

  it "should block any SAMBA activity incoming on TTK port" do
    @fw.should block("udp from #{inet_ip} 1 to 62.165.53.130 139")
    @fw.should block("udp from #{inet_ip} 1 to 62.165.53.130 137")
    @fw.should block("udp from #{inet_ip} 1 to 62.165.53.130 135")
    @fw.should block("tcp from #{inet_ip} 1 to 62.165.53.130 445")
  end

  $sample_user_ips.each do |ip|
    cisco_ip = "192.168.254.30"
    it "should block user #{ip} trying to access our CISCO #{cisco_ip}" do
      @fw.should block("tcp from #{ip} 1 to #{cisco_ip} 23")
      @fw.should block("tcp from #{ip} 1 to #{cisco_ip} 22")
      @fw.should block("tcp from #{ip} 1 to #{cisco_ip} 161")
      @fw.should block("udp from #{ip} 1 to #{cisco_ip} 161")
    end
  end

  $sample_user_ips.each do |user_ip|
    pkt = "tcp from #{user_ip} #{random_port} to #{inet_ip} 80 in"
    it "should ALLOW: #{pkt}" do
      @fw.should allow(pkt)
    end
  end
  $sample_user_gray_ips.each do |user_ip|
    pkt = "tcp from #{user_ip} #{random_port} to #{inet_ip} 80 out"
    it "should NAT:   #{pkt}" do
      @fw.should nat(pkt,NAT_ID_TTK)
    end
  end
  $sample_user_white_ips.each do |user_ip|
    pkt = "tcp from #{user_ip} #{random_port} to #{inet_ip} 80 out"
    it "should NOT NAT:   #{pkt}" do
      @fw.should_not nat(pkt,NAT_ID_TTK)
    end
    it "should PASS:   #{pkt}" do
      @fw.should pass(pkt)
    end
  end

  describe "USERS -> TELECOM OFFICE" do
    pkts = []
    $sample_user_ips.each do |user_ip|
      %w'80 22 21'.each do |port|
        pkts << "tcp from #{user_ip} #{random_port} to 192.168.250.8 #{port} in"
      end
    end
    should_block pkts
  end

  describe "USERS -> FREE_IPS" do
    pkts = []
    $sample_user_ips.each do |user_ip|
      pkts << "tcp from #{user_ip} #{random_port} to 62.165.61.19 80 in"
      pkts << "udp from #{user_ip} #{random_port} to 62.165.61.19 53 in"
      pkts << "tcp from #{user_ip} #{random_port} to 62.165.61.19 80 out"
      pkts << "udp from #{user_ip} #{random_port} to 62.165.61.19 53 out"

      pkts << "tcp from 62.165.61.19 80 to #{user_ip} #{random_port} in"
      pkts << "udp from 62.165.61.19 53 to #{user_ip} #{random_port} in"
      pkts << "tcp from 62.165.61.19 80 to #{user_ip} #{random_port} out"
      pkts << "udp from 62.165.61.19 53 to #{user_ip} #{random_port} out"
    end
    should_pass pkts
  end

  describe "NETPING, LIGHTCOM -> INET" do
    ($netping_ips + $lightcom_ips).each do |ip|
      pkt = "from #{ip} #{random_port} to #{inet_ip} 80 in"
      it "should BLOCK:\t#{pkt}" do
        @fw.should block(pkt)
      end
    end
  end

  describe "disabled users" do
    describe "INET access" do
      pkts = []
      $disabled_ips.each do |ip|
        pkts << "from #{ip} #{random_port} to #{inet_ip} 80 in"
        pkts << "udp from #{ip} #{random_port} to #{inet_ip} 53 in"
        pkts << "icmp from #{ip} #{random_port} to #{inet_ip}"
      end
      pkts.each do |pkt|
        it "should BLOCK:\t#{pkt}" do
          @fw.should block(pkt)
        end
      end
    end

    describe "FREE_IPS access" do
      pkts = []
      $disabled_ips.each do |ip|
        pkts << "from #{ip} #{random_port} to #{free_ip} 80 in"
        pkts << "udp from #{ip} #{random_port} to #{free_ip} 53 in"
      end
      pkts.each do |pkt|
        it "should PASS:\t#{pkt}" do
          @fw.should pass(pkt)
        end
      end
    end
  end

  describe "INET -> ME (dns, www, etc)" do
    describe "(dns, www, etc)" do
      pkts = []
      pkts << "tcp from #{inet_ip} #{random_port} to 62.165.61.1 80 in"
      pkts << "udp from #{inet_ip} #{random_port} to 62.165.61.1 53 in"
      pkts << "tcp from 62.165.61.1 80 to #{inet_ip} #{random_port} out"
      pkts << "udp from 62.165.61.1 53 to #{inet_ip} #{random_port} out"
      should_pass pkts
    end
    describe "(ftp, mysql, ssh)" do
      pkts = []
      pkts << "tcp from #{inet_ip} #{random_port} to 62.165.61.1 20 in"
      pkts << "tcp from #{inet_ip} #{random_port} to 62.165.61.1 21 in"
      pkts << "tcp from #{inet_ip} #{random_port} to 62.165.61.1 22 in"
      pkts << "tcp from #{inet_ip} #{random_port} to 62.165.61.1 3306 in"
      should_block pkts
    end
  end

  describe "USERS -> ME" do
    describe "(dns, www, etc)" do
      pkts = []
      $sample_user_ips.each do |ip|
        pkts << "tcp from #{ip} #{random_port} to 62.165.61.1 80 in"
        pkts << "udp from #{ip} #{random_port} to 62.165.61.1 53 in"
        pkts << "tcp from 62.165.61.1 80 to #{ip} #{random_port} out"
        pkts << "udp from 62.165.61.1 53 to #{ip} #{random_port} out"
      end
      should_pass pkts
    end
    describe "(ftp, mysql, ssh)" do
      pkts = []
      $sample_user_ips.each do |ip|
        pkts << "tcp from #{ip} #{random_port} to 62.165.61.1 20 in"
        pkts << "tcp from #{ip} #{random_port} to 62.165.61.1 21 in"
        pkts << "tcp from #{ip} #{random_port} to 62.165.61.1 22 in"
        pkts << "tcp from #{ip} #{random_port} to 62.165.61.1 3306 in"
      end
      should_block pkts
    end
  end
end
