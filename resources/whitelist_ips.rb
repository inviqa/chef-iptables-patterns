#
# Cookbook Name:: iptables-patterns
# Resource:: whitelist_ips
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

resource_name :iptables_patterns_whitelist_ips
provides :iptables_patterns_whitelist_ips

property :chain_firewall_name, String, name_property: true
property :tcp_ports, Array, default: []
property :udp_ports, Array, default: []
property :firewalled_chains, Array, default: ['INPUT', 'FORWARD']
property :whitelist_action, String, default: 'RETURN'
property :whitelist_ipv4_addresses, Array, default: []
property :whitelist_ipv6_addresses, Array, default: []
property :enabled_ip_versions, Array, default: [4, 6]

actions [:create]
default_action :create
