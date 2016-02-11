---
title: DDoS Open Threat Signaling Architecture
docname: draft-mortensen-dots-architecture-00
date: 2016-02-11

area: Security
wg: DOTS
kw: Internet-Draft
cat: info

coding: us-ascii
pi:
  toc: yes
  sortrefs: no
  symrefs: yes

author:
      -
        ins: A. Mortensen
        name: Andrew Mortensen
        org: Arbor Networks, Inc.
        street: 2727 S. State St
        city: Ann Arbor, MI
        code: 48104
        country: United States
        email: amortensen@arbor.net
      -
        ins: F. Andreasen
        name: Flemming Andreasen
        org: Cisco Systems, Inc.
        street:
        -
        city:
        -
        code:
        -
        country: United States
        email: fandreas@cisco.com
      -
        ins: C. Gray
        name: Christopher Gray
        org: Comcast, Inc.
        street:
        -
        city:
        -
        code:
        -
        country: United States
        email: Christopher_Gray3@cable.comcast.com
      -
        ins: N. Teague
        name: Nik Teague
        org: Verisign, Inc.
        street:
        -
        city:
        -
        code:
        -
        country: United States
        email: nteague@verisign.com

normative:
  RFC2119:

informative:
  I-D.ietf-dots-requirements:
  I-D.ietf-dots-use-cases:

--- abstract

This document describes an architecture for establishing and maintaining
DDoS Open Threat Signaling (DOTS) within and between networks. The document
makes no attempt to suggest protocols or protocol extensions, instead focusing
on architectural relationships, components and concepts used in a DOTS
deployment, as well as obstacles confronting a network operator looking to
enable DOTS.

--- middle

Introduction
============

Signaling the need for help defending against an active distributed denial
of service (DDoS) attack requires a common understanding of mechanisms and
roles among the parties coordinating attack response. The proposed signaling
layer and supplementary messaging is the focus of DDoS Open Threat Signaling
(DDoS). DOTS proposes to standardize a method of coordinating defensive
measures among willing peers to mitigate attacks quickly and efficiently.

This document describes an architecture used in establishing, maintaining or
terminating a DOTS relationship in a network or between networks. DOTS
enables hybrid attack responses, coordinated locally at or near the target of
an active attack, as well as closer to attack sources in the network path.


Terminology     {#terminology}
-----------

### Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.


### Definition of Terms

The following terms are used to define relationships between elements,
the data they exchange, and methods of communication among them:

DDoS:
: A distributed denial-of-service attack, in which attack traffic originates
  from widely distributed sources. DDoS attacks are intended to cause ai
  negative impact on the availability of servers, services, applications,
  and/or other functionality of an attack target.

attack target:
: the network-enabled service, application, server, or some collection thereof,
  on which a DDoS attack is focused.

attack telemetry:
: collected network traffic characteristics enabling detection, classification
  and possible traceback of a DDoS attack.

countermeasure:
: An action or series of actions undertaken to distinguish and filter out
  DDoS attack traffic from valid traffic destined for an attack target.

mitigation:
: A defensive response against a detected DDoS attack, performed by an entity
  in the network path between attack sources and the attack target, either
  through inline deployment or some form of traffic diversion, consisting of
  one or more countermeasures. The form mitigation takes is out of scope for
  this document.

mitigator:
: A network element capable of performing mitigation of a detected DDoS attack.

DOTS client:
: A DOTS-aware network element requesting attack response coordination with
  another DOTS-aware element, with the expectation that the remote element is
  capable of helping fend off the attack against the client.

DOTS server:
: A DOTS-aware network element handling and responding to messages from a
  DOTS client. The DOTS server MAY enable mitigation on behalf of the DOTS
  client, if requested, by communicating the DOTS client's request to the
  mitigator and relaying any mitigator feedback to the client. A DOTS server
  may also be a mitigator.

DOTS relay:
: A DOTS-aware network element positioned between a DOTS server and a DOTS
  client. A DOTS relay receives messages from a DOTS client and relays them
  to a DOTS server, and similarly passes messages from the DOTS server to the
  DOTS client.

DOTS agents:
: A collective term for DOTS clients, servers and relays.

signal channel:
: A bidirectional, mutually authenticated communication layer between DOTS
  agents characterized by resilience even in conditions leading to severe
  packet loss, such as a volumetric DDoS attack causing network congestion.

DOTS signal:
: A concise authenticated status/control message transmitted between DOTS
  agents, used to indicate client's need for mitigation, as well as to convey
  the status of any requested mitigation.

heartbeat:
: A keep-alive message transmitted between DOTS agents over the signal channel,
  used to measure peer health. Heartbeat functionality is not required to be
  distinct from signal.

client signal:
: A message sent from a DOTS client to a DOTS server over the signal channel,
  possibly traversing a DOTS relay, indicating the DOTS client's need for
  mitigation, as well as the scope of any requested mitigation, optionally
  including detected attack telemetry to supplement server-initiated
  mitigation.

server signal:
: A message sent from a DOTS server to a DOTS client over the signal channel.
  Note that a server signal is not a response to client signal, but a DOTS
  server-initiated status message sent to the DOTS client, containing
  information about the status of any requested mitigation and its efficacy.

data channel:
: A secure communication layer between client and server used for infrequent
  bulk exchange of data not easily or appropriately communicated through the
  signal channel under attack conditions.

blacklist:
: a list of source addresses or prefixes from which traffic should be blocked.

whitelist:
: a list of source addresses or prefixes from which traffic should always be
  allowed, regardless of contradictory data gleaned in a detected attack.


Scope           {#scope}
-----

This document defines an architecture for the proposed DOTS standard in the
IETF.

In this architecture, DOTS clients and servers communicate using the signaling
mechanism established in the proposed DOTS standard. As a result of signals
from a DOTS client, the DOTS server may modify the network path of traffic
destined for the attack target or targets, for example by diverting traffic
to a scrubbing center. Packets deemed part of an active attack may be dropped.

The architecture presented here is assumed to be applicable across network
administrative domains--as, for example, between an enterprise domain and
the domain of a third-party attack scrubbing service--as well as to a single
administrative domain. DOTS is generally assumed to be most effective when
aiding coordination of attack response between two or more participating
network domains, but single domain scenarios are worth investigating elsewhere. 


Assumptions     {#assumptions}
-----------

This document makes the following assumptions:

* The network or networks in which DOTS is deployed are assumed to offer the required connectivity between DOTS agents and any intermediary network elements, but the architecture imposes no additional limitations on the form of connectivity.

* There is no universal DDoS attack scale threshold triggering a coordinated response across network administrative domains. A network domain administrator, or service or application owner may arbitrarily set attack scale threshold triggers, or manually send requests for mitigation.

* The mitigation capacity of networks requesting [AM: need def] coordinated attack response is opaque to any network receiving and potentially agreeing to intervene.

* The mitigation capacity of networks receiving requests for coordinated attack response is opaque to the network sending the request. The network receiving the DOTS client signal may or may not have sufficient capacity to filter all or even the majority of DDoS attack traffic directed at a target.

* DOTS client and server signals, as well as messages sent through the data channel, are sent across any transit networks with the same probability of delivery of any other traffic between the DOTS client network and the DOTS server network. Any encapsulation required for successful delivery is left untouched by transit network elements.

* The architecture allows for, but does not assume, the presence of Quality of Service (QoS) policy agreements between DOTS-enabled peer networks aimed at ensuring delivery of DOTS signals between DOTS agents.


Architecture
============
DOTS enables a target that is under a Distributed Denial-of-Service (DDoS) attack to signal another entity for help in mitigating the DDoS attack. The basic high-level DOTS reference architecture is illustrated in Figure X1


~~~~~
      Mitigator ~~~~~~~~~~ DOTS Server
                             |     |
                             |     +---+
                             |         |
                             |       DOTS Relay
                             |         |
                             |     +---+
                             |     |
     Attack Target ~~~~~~~ DOTS Client
~~~~~


A simple example instantiation of the DOTS architecture could be an enterprise as the attack target for a volumetric DDoS attack, and an upstream DDoS mitigation service as the Mitigator. The enterprise (attack target) is connected to the Internet via a link that is getting saturated, and the enterprise suspects it is under DDoS attack. The enterprise has a DOTS client, which obtains information about the DDoS attack, and signals the DOTS server for help in mitigating the attack. The communication may be direct from the DOTS client to the DOTS Server, or it may traverse one or more DOTS Relays, which act as intermediaries. The DOTS Server in turn invokes one or more mitigators, which are tasked with mitigating the actual DDoS attack, and hence aim to suppress the attack traffic while allowing valid traffic to reach the attack target. 

The scope of the DOTS specifications is the interface(s) between the DOTS client, DOTS server, and DOTS relay. The interface(s) to the attack target and the mitigator are out of scope of DOTS. Similarly, the operation of both the attack target and the mitigator are out of scope of DOTS. Thus, DOTS neither speficies how an attack target decides it is under DDoS attack, nor does DOTS specify how a mitigator may actually mitigate it. 

[**FSA**: *However, should we say something about operational considerations nevertheless. In particular, I'm thinking about M:N relationships, which doesn't necessarily seem wise. Also, since we may be getting involved in traffic redirection, is there something to say about authorization of such requests - should a DOTS server just blindly redirect traffic for mitigation purposes, etc. based on what any DOTS client tells it ?*]

As illustrated in Figure X2, there are two interfaces between the DOTS Server and the DOTS Client (and possibly the DOTS Relay). 

~~~~~
    +----------------+                                 +----------------+
    |                | <------- Signal Channel ------> |                |
    |   DOTS Client  |                                 |  DOTS Server   |
    |                | <=======  Data Channel  ======> |                |
    +----------------+                                 +----------------+
~~~~~

The primary purpose of the signal channel is for the DOTS client to ask the DOTS server for help in mitigating an attack, and for the DOTS server to inform the DOTS client about the status of such mitigation. The DOTS client does this by sending a client signal, which contains information about the attack target. The client signal may also include telemetry information about the attack, if the DOTS client has such information available. The DOTS Server in turn sends a server signal to inform the DOTS client of whether it will honor the mitigation request. Assuming it will, the DOTS Server initiates attack mitigation, and periodically informs the DOTS client about the status of the mitigation. Similarly, the DOTS client periodically informs the DOTS server about the client's status, which at a minimum provides client (attack target) health information, but it may also include telemetry information about the attack as it is now seen by the client. At some point, the DOTS client or the server may decide to terminate the server-side attack mitigation, which it indicates to the DOTS peer agent (DOTS client or server) over the signal channel. Note that the signal channel may need to operate over a link that is experiencing a DDoS attack and hence is subject to very severe packet loss.  

[**FSA**: *Requirements document talks about having an always-on signal channel with on-going status messages - discuss further*]

While DOTS is able to function with just the signal channel, the addition of the DOTS data channel provides for additional and more efficient capabilities. The primary purpose of the data channel is to support DOTS related configuration and policy information between the DOTS client and the DOTS server. Examples of such information include
* Defining names or aliases for attack targets (resources). Those names can be used in subsequent signal channel exchanges to more efficiently refer to the resources (attack targets) in question. 
* Black-list management, which enables a DOTS client to inform the DOTS server about sources to suppress. 
* White-list, which enables a DOTS client to inform the DOTS server about sources that should always be accepted.  

Note that while it is possible to exchange the above information before, during or after a DDoS attack, DOTS requires reliable delivery of the above information and does not provide any special means for ensuring timely delivery of it during an attack. In practice, this means that DOTS entities SHOULD NOT rely on such information being exchanged during a DDoS attack. 


Relationships 
--------------
**[FSA: For discussion]**

* A DOTS Client is associated with one or more DOTS Servers (?)

* A DOTS Client is associated with one or more DOTS Relays (?)

* A DOTS Relay is assocaited with one or more DOTS Clients

* A DOTS Relay is associated with one or more DOTS Servers

* A DOTS Relay is associated with one or more DOTS Relays (graph/hierarchy ?)

* A DOTS Relay logically consists of a DOTS Server and a DOTS Client (?)

* Can a DOTS Client tell if it is talking to a DOTS Server or a DOTS Relay ?

* Can a DOTS Server tell if it is talking to a DOTS Client or a DOTS Relay ?



DOTS Operational Process
------------------------
**[FSA: For discussion]**
Although the scope of DOTS is focused on the signaling and data exchange between the DOTS client, DOTS server and (possibly) the DOTS relay, DOTS is specified with some underlying assumptions around the operational process associated with the use of DOTS. 

1. Before a DOTS client can signal a DOTS server, a relationship needs to be established between the two.

* The relationship involves establishing credentials for mutual authentication. 

* *What about authorization, e.g. in terms of resources we want to protect and hence potentially may be redirecting traffic for ?*


TBD

Concepts
--------

TBD

Components
----------

TBD

Obstacles
---------

TBD

Security Considerations         {#security-considerations}
=======================

TBD

Change Log
==========

