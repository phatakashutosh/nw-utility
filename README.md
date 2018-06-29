# Simple Network Utility
This repository contains an application for Ryu Controller in Software Defined Networking environment to use simple network management utility to implement learning switch modules into network nodes and also deploy firewall policies onto desired node. The application is built as a part of academic research project for Masters course at *SRM Institute of Science and Technology, Chennai, India*.

In this network management application, a network administrator can access information about network resources (i.e. networking nodes) and accordingly network can be setup with assigning role of learning switch or firewall to resources. The application uses RESTful API for reading resources and making live changes in network and security policies. At present, REST for application can be called locally in command line interface using cURL.

## Components of applications
The application is divided into three major components
1) Controller Base
2) Firewall Module
3) Switch Module

### Controller Base
It deals with translating REST requests to appropriate actions to be taken by Ryu Controller on networking nodes. It distinguishes nodes as either learning switch or firewall and load corresponding modules onto nodes. Controller base works with *List of Nodes* and *List of Firewalls* which enable network administrator to make changes (e.g. re-assigning/reshuffling roles, updating flow table entries, etc) nodes in live network.

### Firewall Module
In firewall module, functions required to implement security policies are defined. Upon receiving REST requests related to firewall, the controller base redirect to firewall module to take appropriate actions.

### Switch Module
It is a basic MAC learning switch that frequently send packet_in messages to controller to get neccessary action for source-destination MACs.

## Prerequisite
1) Ryu Framework
2) OpenFlow switch

For Ryu Installation click [here](https://osrg.github.io/ryu-book/en/html/installation_guide.html). As given in Ryu installation guide SDN environment can be created using either Mininet Emulator or Open vSwitch application on linux OS. It is also possible to create SDN environment in GNS3 using multilayer switch appliances - [Open vSwitch](http://docs.gns3.com/appliances/openvswitch.html) and/or [Open vSwitch Management](http://docs.gns3.com/appliances/openvswitch-management.html).

## Useful links for reference
* [Ryu Framework](https://osrg.github.io/ryu-book/en/Ryubook.pdf)
* [Ryu Documentation](https://ryu.readthedocs.io/en/latest/getting_started.html)
* [Open vSwitch commands](http://www.openvswitch.org/support/dist-docs/)
