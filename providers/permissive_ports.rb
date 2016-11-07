#
# Cookbook Name:: iptables-patterns
# Provider:: permissive_ports
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

use_inline_resources

action :create do
  include_recipe 'iptables-ng'

  chain_firewall_name = new_resource.chain_firewall_name
  chain_firewall_name = "#{chain_firewall_name.upcase}-FIREWALL"

  iptables_ng_chain chain_firewall_name do
    action :create
  end

  iptables_ng_rule chain_firewall_name do
    chain 'INPUT'
    rule "--jump #{chain_firewall_name}"
  end

  iptables_ng_rule '10-local' do
    chain chain_firewall_name
    rule '--in-interface lo --jump RETURN'
  end

  # cleanup old versions of the rule
  iptables_ng_rule "10-icmp" do
    chain chain_firewall_name
    action :delete
  end

  node['iptables-ng']['enabled_ip_versions'].each do |version|
    case version
    when 6
      icmp = 'ipv6-icmp'
    else
      icmp = 'icmp'
    end

    iptables_ng_rule "10-icmp-ipv#{version}" do
      chain chain_firewall_name
      rule "--protocol #{icmp} --jump RETURN"
      ip_version version.to_i
    end
  end

  new_resource.allowed_incoming_ports.each_pair do |rule, port|
    iptables_ng_rule "20-#{rule}" do
      chain chain_firewall_name
      if port
        rule "--protocol tcp --dport #{port} --jump RETURN"
      else
        action :delete
      end
    end
  end

  iptables_ng_rule '30-established' do
    chain chain_firewall_name
    rule '--match state --state RELATED,ESTABLISHED --jump RETURN'
  end

  new_resource.enabled_ip_versions.each do |version|
    reject_with = case version
                  when 6
                    'icmp6-port-unreachable'
                  else
                    'icmp-port-unreachable'
                  end

    iptables_ng_rule "zzzz-reject_other-ipv#{version}" do
      chain chain_firewall_name
      rule "--jump REJECT --reject-with #{reject_with}"
      ip_version version.to_i
    end
  end
end
