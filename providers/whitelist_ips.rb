#
# Cookbook Name:: iptables-patterns
# Provider:: whitelist_ips
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

  firewall_name = new_resource.chain_firewall_name
  chain_firewall_name = "#{firewall_name.upcase}-FIREWALL"

  iptables_ng_chain chain_firewall_name do
    action :create
  end

  protocols = %w( tcp udp )

  used_protocols = protocols.reject do |protocol|
    new_resource.send("#{protocol}_ports").empty?
  end

  missing_attrs = (protocols - used_protocols).map do |protocol|
    new_resource.send("#{protocol}_ports")
  end

  if used_protocols.empty?
    raise "You must set #{missing_attrs.join(' or ')}."
  end

  new_resource.firewalled_chains.each do |chain|
    iptables_ng_rule "10-#{firewall_name}-firewall-#{chain}" do
      chain chain
      rule used_protocols.map { |protocol|
        ports = new_resource.send("#{protocol}_ports").join(',')
        portmatch = "--destination-ports #{ports}"

        "--protocol #{protocol} --match multiport #{portmatch} --jump #{chain_firewall_name}"
      }
    end
  end

  new_resource.enabled_ip_versions.each do |version|
    reject_with = case version
                  when 6
                    'icmp6-port-unreachable'
                  else
                    'icmp-port-unreachable'
                  end

    addresses = new_resource.send("whitelist_ipv#{version}_addresses")

    iptables_ng_rule "20-#{firewall_name}-firewall-ipv#{version}-addresses" do
      chain chain_firewall_name
      ip_version version.to_i
      if addresses.empty?
        action :delete
      else
        rule addresses.map { |ip|
          "--source #{ip} --jump #{new_resource.whitelist_action.upcase}"
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
