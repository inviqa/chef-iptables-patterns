require 'spec_helper'

describe 'iptables-patterns::frontend_permissive_ports' do
  it 'uses the standard firewall rules on input' do
    describe iptables do
      it { should have_rule('--jump STANDARD-FIREWALL').with_chain('INPUT') }
    end
  end

  it 'uses the standard firewall rules on forward' do
    describe iptables do
      it { should have_rule('--jump STANDARD-FIREWALL').with_chain('FORWARD') }
    end
  end

  it 'allows all local interface traffic' do
    describe iptables do
      it { should have_rule('--in-interface lo --jump ACCEPT').with_chain('STANDARD-FIREWALL') }
    end
  end

  it 'allows all ICMP traffic' do
    describe iptables do
      it { should have_rule('--protocol icmp --jump ACCEPT').with_chain('STANDARD-FIREWALL') }
    end
  end

  it 'allows port 22 to be communicated with' do
    describe iptables do
      it { should have_rule('--protocol tcp --dport 22 --jump ACCEPT').with_chain('STANDARD-FIREWALL') }
    end
  end

  it 'allows port 80 to be communicated with' do
    describe iptables do
      it { should have_rule('--protocol tcp --dport 80 --jump ACCEPT').with_chain('STANDARD-FIREWALL') }
    end
  end

  it 'allows port 443 to be communicated with' do
    describe iptables do
      it { should have_rule('--protocol tcp --dport 443 --jump ACCEPT').with_chain('STANDARD-FIREWALL') }
    end
  end

  it 'allows all established traffic to continue communicating with each other' do
    describe iptables do
      it { should have_rule('--match state --state RELATED,ESTABLISHED --jump ACCEPT').with_chain('STANDARD-FIREWALL') }
    end
  end

  it 'rejects all other ipv4 traffic' do
    describe iptables do
      it { should have_rule('--jump REJECT --reject-with icmp-port-unreachable').with_chain('STANDARD-FIREWALL') }
    end
  end

  it 'rejects all other ipv6 traffic' do
    describe ip6tables do
      it { should have_rule('--jump REJECT --reject-with icmp6-port-unreachable').with_chain('STANDARD-FIREWALL') }
    end
  end
end
