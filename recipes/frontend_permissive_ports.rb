#
# Cookbook Name:: iptables-patterns
# Recipe:: frontend_permissive_ports
#
# Copyright 2016 Inviqa UK LTD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include_recipe 'iptables-ng'

iptables_ng_chain 'STANDARD-FIREWALL'

iptables_ng_rule 'STANDARD-FIREWALL' do
  chain 'INPUT'
  rule '--jump STANDARD-FIREWALL'
end

iptables_ng_rule '10-local' do
  chain 'STANDARD-FIREWALL'
  rule '--in-interface lo --jump ACCEPT'
end

iptables_ng_rule '10-icmp' do
  chain 'STANDARD-FIREWALL'
  rule '--protocol icmp --jump ACCEPT'
end

node['iptables-standard']['allowed_incoming_ports'].each do |rule, port|
  iptables_ng_rule "20-#{rule}" do
    chain 'STANDARD-FIREWALL'
    if port
      rule "--protocol tcp --dport #{port} --jump ACCEPT"
    else
      action :delete
    end
  end
end

iptables_ng_rule "30-established" do
  chain 'STANDARD-FIREWALL'
  rule '--match state --state RELATED,ESTABLISHED --jump ACCEPT'
end

node['iptables-ng']['enabled_ip_versions'].each do |version|
  case version
  when 6
    reject_with = 'icmp6-port-unreachable'
  else
    reject_with = 'icmp-port-unreachable'
  end

  iptables_ng_rule "zzzz-reject_other-ipv#{version}" do
    chain 'STANDARD-FIREWALL'
    rule "--jump REJECT --reject-with #{reject_with}"
    ip_version version.to_i
  end
end

begin
  f2b_service = resources(:service => 'fail2ban')
  f2b_service.subscribes :restart, 'ruby_block[restart_iptables]', :delayed
rescue Chef::Exceptions::ResourceNotFound
  # fail2ban service doesn't exist, so doesn't need to restart after iptables
end
