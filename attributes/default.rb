default['iptables-patterns']['firewalls'] = ['standard']

default['iptables-standard']['name'] = 'standard'
default['iptables-standard']['type'] = 'permissive_ports'
default['iptables-standard']['allowed_incoming_ports'] = {
  'http' => 'http',
  'https' => 'https',
  'ssh' => 'ssh'
}

default['iptables-whitelist-example']['name'] = 'example'
default['iptables-whitelist-example']['type'] = 'whitelist_ips'
default['iptables-whitelist-example']['firewalled_chains'] = %w(INPUT FORWARD)
default['iptables-whitelist-example']['tcp_ports'] = [80, 443, 1080]
default['iptables-whitelist-example']['udp_ports'] = []
default['iptables-whitelist-example']['whitelist_action'] = 'RETURN'
default['iptables-whitelist-example']['whitelist_ipv4_addresses'] = [
  '127.0.0.1', # Allow localhost to access services
]
default['iptables-whitelist-example']['whitelist_ipv6_addresses'] = [
  '::1' # Allow localhost to access services
]
