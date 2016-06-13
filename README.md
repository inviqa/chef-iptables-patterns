iptables-patterns Cookbook
==========================

Generate an iptables configuration that can open ports to the world or to select
whitelisted IPs.

Uses `iptables-ng` ( https://supermarket.chef.io/cookbooks/iptables-ng ) to do 
the heavy lifting.

How to use this cookbook
------------------------

### Allowing all traffic to ports

The `frontend_permissive_ports` recipe determines which ports are open and closed to external traffic on the server.
By default, it will set up a `STANDARD-FIREWALL` chain that allows communication from all IP addresses to ports:

- 22 (ssh)
- 80 (http)
- 443 (https)

The local interface, lo, will be allowed to talk to itself, so 127.0.0.1 on all ports will function.

Any IP address will be able to ping the server.
See https://security.stackexchange.com/questions/22711/is-it-a-bad-idea-for-a-firewall-to-block-icmp for an interesting
discussion about this.

Any RELATED or ESTABLISHED traffic will also be let through.

Any other traffic will be rejected with an icmp-port-unreachable or icmp6-port-unreachable response.

You can override the opened ports by defining more ports in attributes:
```
node['iptables-standard']['allowed_incoming_ports'] = {
  'rsync' => 'rsync',
  'non-standard-software' => '12345'
}
```

The ports for each item in the array are internally mapped by iptables to those defined in /etc/services if not port numbers.

If you want to remap the port numbers of existing ports, you can again do so via attributes:
```
node['iptables-standard']['allowed_incoming_ports'] = {
  'http' => '8080',
  'https' => false
}
```
This will create a firewall with http port 8080, along with the default ssh port as inherited from the cookbook attributes, leaving the https port blocked.



### Whitelisting IPs to ports

The `whitelist_ip_ports` recipe can write out rules for many different custom firewall chains.
This builds upon the `frontend_permissive_ports` recipe which determines which ports are open, to then determine
which IPs the ports are actually open to.

Any non-whitelisted traffic will be dropped.

For every firewall chain that you wish to create, add the name to this firewalls array:
`node['iptables-patterns']['firewalls'] = ['readme']`

This will cause the recipe to pick up on `node['iptables-readme']`.

For every firewall chain in the firewalls array, the following is expected:

* `node['iptables-readme']['name'] = 'readme'` - the name of the firewall chain

* `node['iptables-readme']['type'] = 'whitelist_ips'` - use the whitelist_ips LWRP instead of the permissive_ports LWRP.

* `node['iptables-readme']['firewalled_chains'] = ['INPUT', 'FORWARD']` - which standard firewall chains should be used to
hook into the new one.

* `node['iptables-readme']['tcp_ports']` = [80, 443, 1080]` - which TCP ports should be filtered through the new firewall
chain. This should contain at least the ports that are in `node['iptables-standard']['allowed_incoming_ports']` for any
traffic from the whitelisted IPs to not be rejected.

* `node['iptables-readme']['udp_ports'] = []` - which UDP ports should be filtered through the new firewall chain

* `node['iptables-readme']['whitelist_action'] = 'RETURN'` - what to do when a whitelisted IP is matched. 'RETURN' is
recommended, rather than 'ACCEPT' as there may be further firewall chains that filter traffic more.

* The IPv4 addresses that are allowed to communicate with the server, to the TCP and UDP ports defined earlier:
```ruby
node['iptables-readme']['whitelist_ipv4_addresses'] = [
  '127.0.0.1', # Allow localhost to access services
  '1.2.3.4',
  '5.6.7.8/32'
]
```

* The IPv6 addresses that are allowed to communicate with the server, to the TCP and UDP ports defined earlier:
```ruby
node['iptables-readme']['whitelist_ipv6_addresses'] = [
  '::1' # Allow localhost to access services
]
```

### LWRPs

#### iptables_patterns_permissive_ports

Use the LWRP `iptables_patterns_permissive_ports` to define which ports are open for the server.
This is used by the `frontend_permissive_ports` recipe and as it stands, you cannot use both the recipe and the LWRP
together or indeed two usages of the LWRP, due to the action of a non-whitelisted port number being to drop the traffic.

As it is used by the frontend_permissive_ports recipe, see it's description above in `Allowing all traffic to ports`
for what it will do!

```ruby
iptables_patterns_permissive_ports 'name' do
  allowed_incoming_ports {'ssh' => 'ssh', 'http' => '8080'}
  action :create
end
```

Attributes:
<table>
  <thead>
    <tr>
      <th>Attribute</th>
      <th>Description</th>
      <th>Example</th>
      <th>Default</th>
    </tr>
  </thead>

  <tbody>
    <tr>
      <td>chain_firewall_name</td>
      <td>name of the firewall chain, will be capitalised and have "-FIREWALL" added</td>
      <td><tt>example</tt></td>
      <td><tt></tt></td>
    </tr>
    <tr>
      <td>allowed_incoming_ports</td>
      <td>mapping of rule names to ports or service names (as defined in /etc/services)</td>
      <td><tt>{ ssh: 'ssh', http: 8080 }</tt></td>
      <td><tt>{ ssh: 'ssh' }</tt> (to avoid locking the user out after applying!)</td>
    </tr>
    <tr>
      <td>enabled_ip_versions</td>
      <td>which IP versions are in use (4 and 6, just 4, just 6)</td>
      <td><tt>[4, 6]</tt></td>
      <td><tt>[4, 6]</tt></td>
    </tr>
  </tbody>
</table>

#### iptables_patterns_whitelist_ips

Use the LWRP `iptables_patterns_whitelist_ips` to lock down the specified ports to be able to be accessed by whitelisted
IPs only.

This is used by the `whitelist_ip_ports` recipe and as it stands. Usages of the LWRP and recipe are allowed but you
should not use this to define more than one whitelist for the same port, as the first filter of the port would drop
the traffic for non-whitelisted IPs.

As it is used by the whitelist_ip_ports recipe, see it's description above in `Whitelisting IPs to ports`
for what it will do!

```ruby
iptables_patterns_whitelist_ips 'web' do
  tcp_ports [80, 443]
  whitelist_ipv4_addresses ['127.0.0.1', '1.2.3.4']
  whitelist_ipv6_addresses ['::1']
  action :create
end

iptables_patterns_whitelist_ips 'office-ssh' do
  tcp_ports [22]
  whitelist_ipv4_addresses ['5.6.7.8']
  whitelist_ipv6_addresses ['::1']
  action :create
end
```

Attributes:
<table>
  <thead>
    <tr>
      <th>Attribute</th>
      <th>Description</th>
      <th>Example</th>
      <th>Default</th>
    </tr>
  </thead>

  <tbody>
    <tr>
      <td>chain_firewall_name</td>
      <td>name of the firewall chain, will be capitalised and have "-FIREWALL" added</td>
      <td><tt>example</tt></td>
      <td><tt></tt></td>
    </tr>
    <tr>
      <td>tcp_ports</td>
      <td>Array of ports (in numeric form) to filter to whitelisted IPs using TCP</td>
      <td><tt>[80, 443]</tt></td>
      <td><tt>[]</tt></td>
    </tr>
    <tr>
      <td>udp_ports</td>
      <td>Array of ports (in numeric form) to filter to whitelisted IPs using UDP</td>
      <td><tt>[10800, 10801]</tt></td>
      <td><tt>[]</tt></td>
    </tr>
    <tr>
      <td>firewalled_chains</td>
      <td>Array of existing chains (in string form) to insert our filtering chain into</td>
      <td><tt>['INPUT', 'FILTER']</tt></td>
      <td><tt>['INPUT', 'FILTER']</tt></td>
    </tr>
    <tr>
      <td>whitelist_ipv4_addresses</td>
      <td>Array of whitelisted IPv4 addresses to allow to interact with the ports</td>
      <td><tt>['127.0.0.1', '1.2.3.4']</tt></td>
      <td><tt>[]</tt></td>
    </tr>
    <tr>
      <td>whitelist_ipv6_addresses</td>
      <td>Array of whitelisted IPv6 addresses to allow to interact with the ports</td>
      <td><tt>['::1']</tt></td>
      <td><tt>[]</tt></td>
    </tr>
    <tr>
      <td>enabled_ip_versions</td>
      <td>which IP versions are in use (4 and 6, just 4, just 6)</td>
      <td><tt>[4, 6]</tt></td>
      <td><tt>[4, 6]</tt></td>
    </tr>
  </tbody>
</table>

Contributing
------------

1. Fork the repository on Github
2. Create a named feature branch (like `add_component_x`)
3. Write you change
4. Write tests for your change (if applicable)
5. Run the tests, ensuring they all pass
6. Submit a Pull Request using Github

Testing
-------

We use the following testing tools on this project, which can be installed by running `bundle install`.
These will all run when you perform `bundle exec rake test`, however if you wish to know how to run them individually,
they are listed below.

1. RSpec/ChefSpec for spec style TDD: `bundle exec rspec`
2. Test Kitchen for TDD and testing out individual recipes on a test Virtual Machine: `bundle exec kitchen test`
3. Foodcritic to catch Chef specific style/correctness errors: `bundle exec foodcritic . -f any -C`
4. Rubocop to catch Ruby style "offenses": `bundle exec rubocop`


Supermarket share
-----------------

[stove](http://sethvargo.github.io/stove/) is used to create git tags and
publish the cookbook on supermarket.chef.io.

To tag/publish you need to be a contributor to the cookbook on Supermarket and
run:

```
$ stove login --username <your username> --key ~/.chef/<your username>.pem
$ rake publish
```

It will take the version defined in metadata.rb, create a tag, and push the
cookbook to https://supermarket.chef.io/cookbooks/iptables-patterns


License and Authors
-------------------
- Author:: Kieren Evans
- Author:: Andy Thompson

```text
Copyright:: 2016 Inviqa UK LTD

See LICENSE file
```
