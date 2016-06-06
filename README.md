iptables-patterns Cookbook
==========================

Generate an iptables configuration that can open ports to the world or to select
whitelisted IPs.

Uses `iptables-ng` ( https://supermarket.chef.io/cookbooks/iptables-ng ) to do 
the heavy lifting.

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

    RSpec/ChefSpec for spec style TDD: `bundle exec rspec`
    Test Kitchen for TDD and testing out individual recipes on a test Virtual Machine: `bundle exec kitchen test`
    Foodcritic to catch Chef specific style/correctness errors: `bundle exec foodcritic . -f any -C`
    Rubocop to catch Ruby style "offenses": `bundle exec rubocop`


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
