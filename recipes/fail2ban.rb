#
# Cookbook Name:: iptables-patterns
# Recipe:: fail2ban
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

begin
  f2b_service = resources('service[fail2ban]')
  f2b_service.subscribes :restart, 'ruby_block[restart_iptables]', :delayed
rescue Chef::Exceptions::ResourceNotFound
  log 'fail2ban service does not exist, so does not need to restart after iptables' do
    level :info
  end
end
