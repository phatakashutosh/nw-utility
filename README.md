# Simple Network Utility
This repository contains an application for Ryu Controller in Software Defined Networking environment to use simple network management utility to implement learning switch modules into network nodes and also deploy firewall policies onto desired node. The application is built as a part of academic research project for Masters course at SRM Institute of Science and Technology, Chennai, India.
In this network management application, a network administrator can access information about network resources (i.e. networking nodes) and accordingly network can be setup with assigning role of learning switch or firewall to resources. The application uses RESTful API for reading resources and making live changes in network and security policies. At present, REST for application can be called locally in command line interface using cURL.

# Components of applications
The application is divided into three major components
1) Controller Base
2) Firewall Module
3) Switch Module
