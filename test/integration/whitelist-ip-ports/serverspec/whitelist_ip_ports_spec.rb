require 'spec_helper'

describe 'iptables-patterns::whitelist_ip_ports' do
  it 'uses the test firewall rules on input' do
    expect(iptables).to have_rule('-j TEST-FIREWALL').with_chain('INPUT')
  end

  it 'forwards all traffic for specific tcp ports through the whitelist firewall for input' do
    expect(iptables).to have_rule('-p tcp -m multiport --dports 22,80 -j TEST-FIREWALL').with_chain('INPUT')
  end

  it 'forwards all traffic for specific tcp ports through the whitelist firewall for forward' do
    expect(iptables).to have_rule('-p tcp -m multiport --dports 22,80 -j TEST-FIREWALL').with_chain('FORWARD')
  end

  it 'forwards all traffic for specific udp ports through the whitelist firewall for input' do
    expect(iptables).to have_rule('-p udp -m multiport --dports 1090 -j TEST-FIREWALL').with_chain('INPUT')
  end

  it 'forwards all traffic for specific udp ports through the whitelist firewall for forward' do
    expect(iptables).to have_rule('-p udp -m multiport --dports 1090 -j TEST-FIREWALL').with_chain('FORWARD')
  end

  it 'whitelists ipv4 traffic from the designated IPs' do
    expect(iptables).to have_rule('-s 1.2.3.4/32 -j RETURN').with_chain('TEST-FIREWALL')
    expect(iptables).to have_rule('-s 5.6.7.8/32 -j RETURN').with_chain('TEST-FIREWALL')
    expect(iptables).to have_rule('-s 10.0.2.2/32 -j RETURN').with_chain('TEST-FIREWALL')
  end

  it 'whitelists ipv6 traffic aimed at the ports from the designated IPs' do
    expect(ip6tables).to have_rule('-s ::1/128 -j RETURN').with_chain('TEST-FIREWALL')
  end

  it 'rejects non-whitelisted ipv4 traffic aimed at the ports' do
    expect(iptables).to have_rule('-j REJECT --reject-with icmp-port-unreachable').with_chain('TEST-FIREWALL')
  end

  it 'rejects non-whitelisted ipv6 traffic aimed at the ports' do
    expect(ip6tables).to have_rule('-j REJECT --reject-with icmp6-port-unreachable').with_chain('TEST-FIREWALL')
  end
end
