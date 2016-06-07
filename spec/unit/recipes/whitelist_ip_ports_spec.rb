#
# Cookbook Name:: iptables-patterns
# Spec:: default
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

require 'spec_helper'

describe 'iptables-patterns::whitelist_ip_ports' do
  context 'with default config' do
    cached(:chef_run) { ChefSpec::SoloRunner.new.converge(described_recipe) }

    it 'includes frontend_permissive_ports' do
      expect(chef_run).to include_recipe('iptables-patterns::frontend_permissive_ports')
    end
  end

  context 'with a custom firewall' do
    cached(:chef_run) do
      ChefSpec::SoloRunner.new do |node|
        node.set['iptables-patterns']['firewalls'] = ['test']

        node.set['iptables-test']['tcp_ports'] = ['80', '443']
        node.set['iptables-test']['udp_ports'] = ['1090']

        node.set['iptables-test']['firewalled_chains'] = ['INPUT', 'FORWARD']
        node.set['iptables-test']['whitelist_action'] = 'RETURN'

        node.set['iptables-test']['whitelist_ipv4_addresses'] = ['1.2.3.4', '5.6.7.8']
        node.set['iptables-test']['whitelist_ipv6_addresses'] = ['::1']
      end.converge(described_recipe)
    end

    it 'creates a chain for the custom firewall' do
      expect(chef_run).to create_iptables_ng_chain('TEST-FIREWALL')
    end

    it 'creates a multiport match rule for INPUT covering both tcp and udp ports' do
      expect(chef_run).to create_iptables_ng_rule('10-test-firewall-INPUT').with(
        chain: 'INPUT',
        rule: [
          '--protocol tcp --match multiport --destination-ports 80,443 --jump =TEST-FIREWALL',
          '--protocol udp --match multiport --destination-ports 1090 --jump =TEST-FIREWALL'
        ]
      )
    end

    it 'creates a multiport match rule for FORWARD covering both tcp and udp ports' do
      expect(chef_run).to create_iptables_ng_rule('10-test-firewall-FORWARD').with(
        chain: 'FORWARD',
        rule: [
          '--protocol tcp --match multiport --destination-ports 80,443 --jump =TEST-FIREWALL',
          '--protocol udp --match multiport --destination-ports 1090 --jump =TEST-FIREWALL'
        ]
      )
    end

    it 'creates a whitelisted IPs rule for IPv4' do
      expect(chef_run).to create_iptables_ng_rule('20-test-firewall-ipv4-addresses').with(
        chain: 'TEST-FIREWALL',
        ip_version: 4,
        rule: [
          '--source 1.2.3.4 --jump RETURN',
          '--source 5.6.7.8 --jump RETURN'
        ]
      )
    end

    it 'creates a whitelisted IPs rule for IPv6' do
      expect(chef_run).to create_iptables_ng_rule('20-test-firewall-ipv6-addresses').with(
        chain: 'TEST-FIREWALL',
        ip_version: 6,
        rule: [
          '--source ::1 --jump RETURN'
        ]
      )
    end

    it 'creates a reject catch-all rule for IPv4' do
      expect(chef_run).to create_iptables_ng_rule('30-test-firewall-ipv4-drop').with(
        chain: 'TEST-FIREWALL',
        ip_version: 4,
        rule: '--jump REJECT --reject-with icmp-port-unreachable'
      )
    end

    it 'creates a reject catch-all rule for IPv6' do
      expect(chef_run).to create_iptables_ng_rule('30-test-firewall-ipv6-drop').with(
        chain: 'TEST-FIREWALL',
        ip_version: 6,
        rule: '--jump REJECT --reject-with icmp6-port-unreachable'
      )
    end
  end

  context 'with no whitelisted IPs' do
    cached(:chef_run) do
      ChefSpec::SoloRunner.new do |node|
        node.set['iptables-patterns']['firewalls'] = ['test']

        node.set['iptables-test']['tcp_ports'] = ['80', '443']
        node.set['iptables-test']['udp_ports'] = ['1090']

        node.set['iptables-test']['firewalled_chains'] = ['INPUT', 'FORWARD']
        node.set['iptables-test']['whitelist_action'] = 'RETURN'

        node.set['iptables-test']['whitelist_ipv4_addresses'] = []
        node.set['iptables-test']['whitelist_ipv6_addresses'] = []
      end.converge(described_recipe)
    end

    it 'deletes the whitelisted IPs rule for IPv4' do
      expect(chef_run).to delete_iptables_ng_rule('20-test-firewall-ipv4-addresses')
    end

    it 'deletes the whitelisted IPs rule for IPv6' do
      expect(chef_run).to delete_iptables_ng_rule('20-test-firewall-ipv6-addresses')
    end
  end
end
