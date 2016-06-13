#
# Cookbook Name:: iptables-patterns
# Library:: matchers
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

if defined?(ChefSpec)
  def create_iptables_patterns_permissive_ports(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:iptables_patterns_permissive_ports, :create, resource_name)
  end

  def create_iptables_patterns_whitelist_ips(resource_name)
    ChefSpec::Matchers::ResourceMatcher.new(:iptables_patterns_whitelist_ips, :create, resource_name)
  end
end
