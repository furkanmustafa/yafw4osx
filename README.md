yafw4osx
========

Yet-Another Firewall For OSX

This project is simply an attempt to provide [LittleSnitch](http://www.obdev.at/products/littlesnitch/index.html) like function with more additions, featuring;
 - in a free (as-in-freedom) way, protected with GPL
 - application based proxy settings
 - system wide proxy settings *(includes terminal / background processes)*
 - host based settings
 - dns inception
  - regex based *(or at least with some wildcard option)* dns rules (kind of more flexible /etc/hosts function).
 - statistics
 - interface for other possible uses

*Why note: I would just willingly pay for a commercial solution, if I could completely trust (see sources, compile it myself) and if I could have an option to extend functionality. This is what [Free Software](https://fsf.org) aims to provide anyway.*

*Licensing note: I am note sure if developing this project under GPL license raises any problems with other licenses used in kernel code etc. this project is developed for. Please let me know if there is a problem, hope it's ok*

As I am not an expert on Kernel Development, or Socket Filtering, .. please contribute if you can. Otherwise this will take time.

Milestones
==========
*These are just drafts, feel free to suggest changes*

#### Version 0.1
 - yafw.kext
  - `done` Basic Socket Filter Implementation for Darwin/BSD
  - Packet and Byte Counter
  - A way to read packet/byte statistics from terminal `maybe`
  - Route everything through a fixed local socks proxy (udp, tcp but not icmp)

#### Version 0.2
 - yafw.kext
  - Client Interface for `yafw.app`
  - Intercept DNS requests, have user defined dnses (more flexible than /etx/hosts)
 - yafw.app
  - Register to `yafw.kext`
  - Manage DNS rules
  - Manage Local Socks Proxy Configuration

#### Version 0.5
 - yafw.kext
  - Delegate filtering on client `yafw.app`
  - Basic Implementation for Application based rules
  - Basic Implementation for Host based rules
  - Basic Implementation for User based rules
  - Route different rulesets through different proxies
 - yafw.app
  - Create ssh tunnels on demand
  - Able to manage updates in kext


 ..
 

#### Version 1.0
 - Providing all features mentioned on top.
