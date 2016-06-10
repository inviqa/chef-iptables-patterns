require 'spec_helper'

describe 'iptables-patterns::frontend_permissive_ports' do
  it 'uses the standard firewall rules on input' do
    expect(iptables).to have_rule('-j STANDARD-FIREWALL').with_chain('INPUT')
  end

  it 'allows all local interface traffic' do
    expect(iptables).to have_rule('-i lo -j RETURN').with_chain('STANDARD-FIREWALL')
  end

  it 'allows all ICMP traffic' do
    expect(iptables).to have_rule('-p icmp -j RETURN').with_chain('STANDARD-FIREWALL')
  end

  it 'allows port 22 to be communicated with' do
    expect(iptables).to have_rule('-p tcp -m tcp --dport 22 -j RETURN').with_chain('STANDARD-FIREWALL')
  end

  it 'allows port 80 to be communicated with' do
    expect(iptables).to have_rule('-p tcp -m tcp --dport 80 -j RETURN').with_chain('STANDARD-FIREWALL')
  end

  it 'allows port 443 to be communicated with' do
    expect(iptables).to have_rule('-p tcp -m tcp --dport 443 -j RETURN').with_chain('STANDARD-FIREWALL')
  end

  it 'allows all established traffic to continue communicating with each other' do
    expect(iptables).to have_rule('-m state --state RELATED,ESTABLISHED -j RETURN').with_chain('STANDARD-FIREWALL')
  end

  it 'rejects all other ipv4 traffic' do
    expect(iptables).to have_rule('-j REJECT --reject-with icmp-port-unreachable').with_chain('STANDARD-FIREWALL')
  end

  it 'rejects all other ipv6 traffic' do
    expect(ip6tables).to have_rule('-j REJECT --reject-with icmp6-port-unreachable').with_chain('STANDARD-FIREWALL')
  end
end
