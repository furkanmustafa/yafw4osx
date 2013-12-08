yafw4osx
========

Yet-Another Firewall For OSX

This project is simply an attempt to 

Milestones
==========
*These are just drafts, feel free to suggest changes*

#### Milestone 0.1
 - yafw.kext
  - `done` Basic Socket Filter Implementation for Darwin/BSD
  - Packet and Byte Counter
  - Route everything through a fixed local socks proxy (udp, tcp but not icmp)

#### Milestone 0.2
 - yafw.kext
  - Client Interface for `yafw.app`
  - Intercept DNS requests, have user defined dnses (more flexible than /etx/hosts)
 - yafw.app
  - Register to `yafw.kext`
  - Manage DNS rules
  - Manage Local Socks Proxy Configuration

#### Milestone 0.5
 - yafw.kext
  - Delegate filtering on client `yafw.app`
  - Basic Implementation for Application based rules
  - Basic Implementation for Host based rules
  - Basic Implementation for User based rules
  - Route different rulesets through different proxies
 - yafw.app
  - Create ssh tunnels on demand
  - Able to manage updates in kext

#### Milestone 1.0
..
