#
# Cookbook Name:: iptables-patterns
# Recipe:: whitelist_ip_ports
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

include_recipe 'iptables-patterns::frontend_permissive_ports'

node['iptables-patterns']['firewalls'].each do |firewall_name|
  data = node["iptables-#{firewall_name}"]

  next if data.key? 'type' && data['type'] == 'permissive_ports'

  chain_firewall_name = "#{firewall_name.upcase}-FIREWALL"

  iptables_ng_chain chain_firewall_name do
    action :create
  end

  protocols = %w( tcp udp )

  used_protocols = protocols.reject do |protocol|
    node["iptables-#{firewall_name}"]["#{protocol}_ports"].empty?
  end

  missing_attrs = (protocols - used_protocols).map do |protocol|
    %(node['iptables-#{firewall_name}']['#{protocol}_ports'])
  end

  if used_protocols.empty?
    Chef::Application.fatal! "You must set #{missing_attrs.join(' or ')}."
  end

  node["iptables-#{firewall_name}"]['firewalled_chains'].each do |chain|
    iptables_ng_rule "10-#{firewall_name}-firewall-#{chain}" do
      chain chain
      rule used_protocols.map { |protocol|
        portmatch = "--destination-ports #{node["iptables-#{firewall_name}"]["#{protocol}_ports"].join(',')}"

        "--protocol #{protocol} --match multiport #{portmatch} --jump #{chain_firewall_name}"
      }
    end
  end

  node['iptables-ng']['enabled_ip_versions'].each do |version|
    reject_with = "icmp#{version}-port-unreachable"
    reject_with = 'icmp-port-unreachable' if version.to_i == 4

    iptables_ng_rule "20-#{firewall_name}-firewall-ipv#{version}-addresses" do
      chain chain_firewall_name
      ip_version version.to_i
      if node["iptables-#{firewall_name}"]["whitelist_ipv#{version}_addresses"].empty?
        action :delete
      else
        rule node["iptables-#{firewall_name}"]["whitelist_ipv#{version}_addresses"].map { |ip|
          "--source #{ip} --jump #{node["iptables-#{firewall_name}"]['whitelist_action']}"
        }
        action :create
      end
    end

    iptables_ng_rule "30-#{firewall_name}-firewall-ipv#{version}-drop" do
      chain chain_firewall_name
      ip_version version.to_i
      rule "--jump REJECT --reject-with #{reject_with}"
    end
  end
end
