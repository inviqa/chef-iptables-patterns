require 'spec_helper'

describe 'iptables-patterns::whitelist_ip_ports' do
  it 'uses the test firewall rules on input' do
    describe iptables do
      it { should have_rule('--jump TEST-FIREWALL').with_chain('INPUT') }
    end
  end

  it 'forwards all traffic for specific tcp ports through the whitelist firewall for input' do
    describe iptables do
      it { should have_rule('--protocol tcp --match multiport --destination-port 22,80 --jump TEST-FIREWALL').with_chain('INPUT') }
    end
  end

  it 'forwards all traffic for specific tcp ports through the whitelist firewall for forward' do
    describe iptables do
      it { should have_rule('--protocol tcp --match multiport --destination-port 22,80 --jump TEST-FIREWALL').with_chain('FORWARD') }
    end
  end

  it 'forwards all traffic for specific udp ports through the whitelist firewall for input' do
    describe iptables do
      it { should have_rule('--protocol udp --match multiport --destination-port 1090 --jump TEST-FIREWALL').with_chain('INPUT') }
    end
  end

  it 'forwards all traffic for specific udp ports through the whitelist firewall for forward' do
    describe iptables do
      it { should have_rule('--protocol udp --match multiport --destination-port 1090 --jump TEST-FIREWALL').with_chain('FORWARD') }
    end
  end

  it 'whitelists ipv4 traffic from the designated IPs' do
    describe iptables do
      it { should have_rule('--source 1.2.3.4 --jump RETURN').with_chain('TEST-FIREWALL') }
      it { should have_rule('--source 5.6.7.8 --jump RETURN').with_chain('TEST-FIREWALL') }
      it { should have_rule('--source 10.0.2.2 --jump RETURN').with_chain('TEST-FIREWALL') }
    end
  end

  it 'whitelists ipv6 traffic aimed at the ports from the designated IPs' do
    describe ip6tables do
      it { should have_rule('--source ::1 --jump RETURN').with_chain('TEST-FIREWALL') }
    end
  end

  it 'whitelists ipv6 traffic aimed at the ports from the designated IPs' do
    describe ip6tables do
      it { should have_rule('--source ::1 --jump RETURN').with_chain('TEST-FIREWALL') }
    end
  end

  it 'rejects non-whitelisted ipv4 traffic aimed at the ports' do
    describe iptables do
      it { should have_rule('--jump REJECT --reject-with icmp-port-unreachable').with_chain('TEST-FIREWALL') }
    end
  end

  it 'rejects non-whitelisted ipv6 traffic aimed at the ports' do
    describe ip6tables do
      it { should have_rule('--jump REJECT --reject-with icmp6-port-unreachable').with_chain('TEST-FIREWALL') }
    end
  end
end
