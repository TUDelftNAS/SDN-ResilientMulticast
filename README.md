# SDN-ResilientMulticast
This Ryu application enables (edge) fault-tolerant multicast for an OpenFlow network by installing Fast Failover groups. 

At the moment only IPv4 multicast is supported.

Hosts can join or leave a multicast group by sending an IGMPv3 INCLUDE or EXCLUDE packet to a switch in the network. These packets automatically get taken out of the network and processed by the controller application. At the moment no other IGMPv3 messages are supported.

##Requirements
SDN-ResilientMulticast relies on both [Ryu](https://github.com/osrg/ryu) and [NetworkX](https://github.com/networkx/networkx).

[SPT](SPT.py) and [DST](DST.py) will only work properly with the development version of NetworkX, as they both make use of the weight function functionality when computing shortest paths.

##Modules
The functionality of the application is divided over 3 types of modules:

* [MulticastController](MulticastController.py) is the main module. It is the interface between the application and the network. Installs flows, adds and removes hosts to and from groups, etc.
* To compute the necessary primary and backup trees, MulticastController makes use of a [TreeBuilder](AbstractTreeBuilder.py). This module is responsible for keeping track of all multicast groups and computing and installing all multicast trees. Currently only one TreeBuilder is available: [PerLinkTreeBuilder](PerLinkTreeBuilder.py). PerLinkTreeBuilder enables fault tolerance by installing a new backup tree for every single link it protects in a tree.
* Finally, a tree construction algorithm is used to actually compute the addition of subscribers to specific trees. This way the application can for example construct either [Shortest Path Trees](SPT.py) or [approximations to Dynamic Steiner Trees](DST.py).

The tree construction algorithm should implement the following function:

```join(network, exclude, T, v)```

Where network is a directed graph of the network, exclude is a set of links that should be ignored, T is a tree and v is a host. Join should return a path from the root of T to v.

To change the basic functionality of the application the amount of fault tolerance, the TreeBuilder and the tree construction algorithm can be changed by modifying the following line of [MulticastController](MulticastController.py):

```self.builder = PerLinkTreeBuilder.PerLinkTreeBuilder(3, self, SPT_join) #F,.,join function```

Where PerLinkTreeBuilder can be changed to switch TreeBuilders, 3 can be replaced by any integer and SPT_join can be replaced with any other join function.

##Usage
The application can be started by passing [MulticastController](MulticastController.py) as an argument to ryu-manager with topology discovery enabled:

```PYTHONPATH=. ./bin/ryu-manager repository_location/SDN-ResilientMulticast/MulticastController.py --observe-links```

For more information on Ryu, visit the [Ryu resources list](http://osrg.github.io/ryu/resources.html).

###Fault Tolerance
By default the application is setup to recover from up to 3 link failures. This requires a lot of resources in the form of flow entries and group tables. To change this number replace the 3 in the following line of [MulticastController](MulticastController.py)

```self.builder = PerLinkTreeBuilder.PerLinkTreeBuilder(3, self, SPT_join) #F,.,join function```

by the required number of edge fault tolerance.

##License
[GPL-3](LICENSE)
