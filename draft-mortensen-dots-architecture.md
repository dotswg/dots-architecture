---
title: DDoS Open Threat Signaling Requirements
docname: draft-ietf-dots-requirements-00
date: 2015-10-19

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

* The network or networks in which DOTS is deployed are assumed to offer
  the required connectivity between DOTS agents and any intermediary network
  elements, but the architecture imposes no additional limitations on the
  form of connectivity.

* There is no universal DDoS attack scale threshold triggering a coordinated
  response across network administrative domains. A network domain
  administrator, or service or application owner may arbitrarily set attack
  scale threshold triggers, or manually send requests for mitigation.

* The mitigation capacity of networks requesting [AM: need def] coordinated
  attack response is opaque to any network receiving and potentially agreeing
  to intervene.

* The mitigation capacity of networks receiving requests for coordinated
  attack response is opaque to the network sending the request. The network
  receiving the DOTS client signal may or may not have sufficient capacity to
  filter all or even the majority of DDoS attack traffic directed at a target.

* DOTS client and server signals, as well as messages sent through the data
  channel, are sent across any transit networks with the same probability of
  delivery of any other traffic between the DOTS client network and the DOTS
  server network. Any encapsulation required for successful delivery is left
  untouched by transit network elements.

* The architecture allows for, but does not assume, the presence of Quality of
  Service (QoS) policy agreements between DOTS-enabled peer networks aimed at
  ensuring delivery of DOTS signals between DOTS agents.


Architecture
============

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

