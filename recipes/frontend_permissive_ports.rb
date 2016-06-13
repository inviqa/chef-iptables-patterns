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


node['iptables-patterns']['firewalls'].each do |firewall_name|
  data = node["iptables-#{firewall_name}"]

  if data.key? 'type' && data['type'] == 'permissive_ports'
    iptables_patterns_permissive_ports data['name'] do
      allowed_incoming_ports data['allowed_incoming_ports']
      enabled_ip_versions node['iptables-ng']['enabled_ip_versions']
      action :create
    end
  end
end
