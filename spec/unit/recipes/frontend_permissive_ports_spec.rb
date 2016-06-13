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

describe 'iptables-patterns::frontend_permissive_ports' do
  let(:chain_name) { 'STANDARD-FIREWALL' }

  shared_examples 'standard firewall' do
    %w(
      http
      https
      ssh
    ).each do |rule|
      it "creates a rule for #{rule}" do
        expect(chef_run).to create_iptables_ng_rule("20-#{rule}").with(
          chain: chain_name,
          rule: "--protocol tcp --dport #{rule} --jump RETURN"
        )
      end
    end

    it 'creates a chain for the standard firewall' do
      expect(chef_run).to create_iptables_ng_chain(chain_name)
    end

    it 'creates a loopback rule' do
      expect(chef_run).to create_iptables_ng_rule('10-local').with(
        chain: chain_name,
        rule: '--in-interface lo --jump RETURN'
      )
    end

    it 'creates an icmp rule' do
      expect(chef_run).to create_iptables_ng_rule('10-icmp').with(
        chain: chain_name,
        rule: '--protocol icmp --jump RETURN'
      )
    end

    it 'creates an established rule' do
      expect(chef_run).to create_iptables_ng_rule('30-established').with(
        chain: chain_name,
        rule: '--match state --state RELATED,ESTABLISHED --jump RETURN'
      )
    end

    it 'creates a reject rule for ipv4' do
      expect(chef_run).to create_iptables_ng_rule('zzzz-reject_other-ipv4').with(
        chain: chain_name,
        rule: '--jump REJECT --reject-with icmp-port-unreachable',
        ip_version: 4
      )
    end

    it 'creates a reject rule for ipv6' do
      expect(chef_run).to create_iptables_ng_rule('zzzz-reject_other-ipv6').with(
        chain: chain_name,
        rule: '--jump REJECT --reject-with icmp6-port-unreachable',
        ip_version: 6
      )
    end
  end

  context 'with default config' do
    cached(:chef_run) { ChefSpec::SoloRunner.new.converge(described_recipe) }

    it_behaves_like 'standard firewall'
  end

  context 'with additonal config' do
    rules = {
      'rsync' => 'rsync',
      'non-standard-software' => '12345'
    }

    cached(:chef_run) do
      ChefSpec::SoloRunner.new do |node|
        node.set['iptables-standard']['allowed_incoming_ports'] = rules
      end.converge(described_recipe)
    end

    it 'creates the additional mappings' do
      rules.each do |rule, port|
        expect(chef_run).to create_iptables_ng_rule("20-#{rule}").with(
          chain: chain_name,
          rule: "--protocol tcp --dport #{port} --jump RETURN"
        )
      end
    end

    it_behaves_like 'standard firewall'
  end

  context 'with remap config' do
    rules = {
      'http' => 8080,
      'https' => false
    }

    cached(:chef_run) do
      ChefSpec::SoloRunner.new do |node|
        node.set['iptables-standard']['allowed_incoming_ports'] = rules
      end.converge(described_recipe)
    end

    test_rules = {
      'http' => 8080,
      'ssh' => 'ssh'
    }

    it 'creates the remapped and default rules' do
      test_rules.each do |rule, port|
        expect(chef_run).to create_iptables_ng_rule("20-#{rule}").with(
          chain: chain_name,
          rule: "--protocol tcp --dport #{port} --jump RETURN"
        )
      end
    end

    it 'deletes unmapped rules' do
      expect(chef_run).to delete_iptables_ng_rule('20-https')
    end
  end

  context 'with custom firewall chain name' do
    let(:chain_name) {
      'NONSTANDARD-FIREWALL'
    }

    cached(:chef_run) do
      ChefSpec::SoloRunner.new do |node|
        node.set['iptables-patterns']['standard-firewall']['name'] = 'NONSTANDARD'
      end.converge(described_recipe)
    end

    it 'creates the chain with the correct name' do
      expect(chef_run).to_not create_iptables_ng_rule('STANDARD-FIREWALL')
      expect(chef_run).to create_iptables_ng_rule('NONSTANDARD-FIREWALL')
    end

    it_behaves_like 'standard firewall'
  end
end
