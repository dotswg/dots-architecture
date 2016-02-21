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
: A distributed denial-of-service attack, in which high levels of traffic
  originating from widely distributed sources is directed at a target or
  collection of targets. DDoS attacks are intended to diminish or prevent the
  availability of servers, services, applications, and/or other functionality
  of an attack target.

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
[NT: rough but growing list]

* The existence of agreed DOTS data model(s) and protocol definitions.

* The network or networks in which DOTS is deployed are assumed to offer the
  required connectivity between DOTS agents and any intermediary network
  elements, but the architecture imposes no additional limitations on the form
  of connectivity.

* Congestion and resource exhaustion are intended outcomes of a DDoS attack.
  Some operators may utilize non-impacted paths or networks for DOTS, however,
  it should be assumed that, in the large majority of instances, conditions will
  be hostile and that signaling SHOULD function in all circumstances.

* There is no universal DDoS attack scale threshold triggering a coordinated
  response across network administrative domains. A network domain
  administrator, or service or application owner may arbitrarily set attack
  scale threshold triggers, or manually send requests for mitigation.

* The mitigation capacity and/or capability of networks receiving requests for
  coordinated attack response is opaque to the network sending the request. The
  network receiving the DOTS client signal may or may not have sufficient
  capacity or capability to filter any or all DDoS attack traffic directed at
  a target.

* DOTS client and server signals, as well as messages sent through the data
  channel, are sent across any transit networks with the same probability of
  delivery of any other traffic between the DOTS client network and the DOTS
  server network. Any encapsulation required for successful delivery is left
  untouched by transit network elements.

* The architecture allows for, but does not assume, the presence of Quality of
  Service (QoS) policy agreements between DOTS-enabled peer networks or local
  QoS prioritization aimed at ensuring delivery of DOTS signals between DOTS
  agents.

* There is no assumption that the signal channel and the data channel should
  terminate on the same server and these may be loosely coupled.
  [NT: Redirection may occur within the signal channel but the data channel
  should also allocate signaller and default to the same server if not present?]


Architecture
============
DOTS enables a target that is under a Distributed Denial-of-Service (DDoS)
attack to signal another entity for help in mitigating the DDoS attack. The
basic high-level DOTS reference architecture is illustrated in Figure X1


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


A simple example instantiation of the DOTS architecture could be an enterprise
as the attack target for a volumetric DDoS attack, and an upstream DDoS
mitigation service as the Mitigator. The enterprise (attack target) is
connected to the Internet via a link that is getting saturated, and the
enterprise suspects it is under DDoS attack. The enterprise has a DOTS client,
which obtains information about the DDoS attack, and signals the DOTS server
for help in mitigating the attack. The communication may be direct from the
DOTS client to the DOTS Server, or it may traverse one or more DOTS Relays,
which act as intermediaries. The DOTS Server in turn invokes one or more
mitigators, which are tasked with mitigating the actual DDoS attack, and hence
aim to suppress the attack traffic while allowing valid traffic to reach the
attack target.

The scope of the DOTS specifications is the interface(s) between the DOTS
client, DOTS server, and DOTS relay. The interface(s) to the attack target and
the mitigator are out of scope of DOTS. Similarly, the operation of both the
attack target and the mitigator are out of scope of DOTS. Thus, DOTS neither
speficies how an attack target decides it is under DDoS attack, nor does DOTS
specify how a mitigator may actually mitigate it.

[**FSA**: *However, should we say something about operational considerations nevertheless. In particular, I'm thinking about M:N relationships, which doesn't necessarily seem wise. Also, since we may be getting involved in traffic redirection, is there something to say about authorization of such requests - should a DOTS server just blindly redirect traffic for mitigation purposes, etc. based on what any DOTS client tells it ?*]

As illustrated in Figure X2, there are two interfaces between the DOTS Server
and the DOTS Client (and possibly the DOTS Relay).

~~~~~
    +---------------+                                 +---------------+
    |               | <------- Signal Channel ------> |               |
    |  DOTS Client  |                                 |  DOTS Server  |
    |               | <=======  Data Channel  ======> |               |
    +---------------+                                 +---------------+
~~~~~

The primary purpose of the signal channel is for the DOTS client to ask the
DOTS server for help in mitigating an attack, and for the DOTS server to inform
the DOTS client about the status of such mitigation. The DOTS client does this
by sending a client signal, which contains information about the attack target.
The client signal may also include telemetry information about the attack, if
the DOTS client has such information available. The DOTS Server in turn sends a
server signal to inform the DOTS client of whether it will honor the mitigation
request. Assuming it will, the DOTS Server initiates attack mitigation, and
periodically informs the DOTS client about the status of the mitigation.
Similarly, the DOTS client periodically informs the DOTS server about the
client's status, which at a minimum provides client (attack target) health
information, but it may also include telemetry information about the attack as
it is now seen by the client. At some point, the DOTS client or the server may
decide to terminate the server-side attack mitigation, which it indicates to
the DOTS peer agent (DOTS client or server) over the signal channel. Note that
the signal channel may need to operate over a link that is experiencing a DDoS
attack and hence is subject to very severe packet loss.

[**FSA**: *Requirements document talks about having an always-on signal channel with on-going status messages - discuss further*]

[**AM**:] I don't believe the -00 req draft does, but the -01 draft will mention
it. I think there's a distinction being lost here, though. Although it will be
possible, and possibly desirable in certain situations, in my view the signal
channel should be more or less always on regardless: it reduces the likelihood
of transport-layer crypto handshakes in attack conditions, should minimize NAT
binding timeout incidence, and simplifies distinguishing between an inactive
DOTS agent and one that is unavailable (e.g., unresponsive during attack). The
"always-on" I've been referring to is "always-on" mitigation: the DOTS client
maintains an signal channel session with the DOTS server, but also maintains
its request for help scrubbing traffic bound for a certain client-owned
network address space, regardless of the presence of attack traffic.

While DOTS is able to function with just the signal channel, the addition of
the DOTS data channel provides for additional and more efficient capabilities.
The primary purpose of the data channel is to support DOTS related
configuration and policy information [AM: exchange] between the DOTS client and
the DOTS server. Examples of such information include

* Defining names or aliases for attack targets (resources). Those names can be
  used in subsequent signal channel exchanges to more efficiently refer to the
  resources (attack targets) in question.

* Black-list management, which enables a DOTS client to inform the DOTS server
  about sources to suppress.

* White-list, which enables a DOTS client to inform the DOTS server about
  sources that should always be accepted.

Note that while it is possible to exchange the above information before, during
or after a DDoS attack, DOTS requires reliable delivery of the above
information and does not provide any special means for ensuring timely delivery
of it during an attack. In practice, this means that DOTS entities SHOULD NOT
rely on such information being exchanged during a DDoS attack.


Relationships
-------------
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
Although the scope of DOTS is focused on the signaling and data exchange
between the DOTS client, DOTS server and (possibly) the DOTS relay, DOTS is
specified with some underlying assumptions around the operational process
associated with the use of DOTS.

1. Before a DOTS client can signal a DOTS server, a relationship needs to be established between the two.

* The relationship involves establishing credentials for mutual authentication. 

* *What about authorization, e.g. in terms of resources we want to protect and hence potentially may be redirecting traffic for ?*


TBD

Concepts and Components
=======================

In this section, we describe core DOTS concepts and introduce the basic
components involved in a DOTS signaling session.


Signaling Sessions
------------------

In order for DOTS to be effective as a vehicle for DDoS mitigation requests,
one or more DOTS clients must establish ongoing communication with one or more
DOTS servers. While the preconditions for enabling DOTS in or among network
domains may also involve business relationships, service level agreements, or
other formal or informal understandings between network operators, such
considerations are out of scope for this document.

An established communication layer between DOTS agents is a Signaling Session.
At its most basic, for a DOTS signaling session to exist both signal channel and
data channel must be functioning between DOTS agents. That is, under nominal
network conditions, signals actively sent from a DOTS client are received by the
specific DOTS server intended by the client, and vice versa.

### Establishing the Signaling Session ###

TBD


### Direct Signaling ###

A signaling session may take the form of direct signaling between the DOTS
clients and servers, as shown in Figure N below:

~~~~~
        +-------------+                            +-------------+
        | DOTS client |<------signal channel------>| DOTS server |
        +-------------+                            +-------------+
~~~~~

In the above figure, the signaling session is active while the DOTS client
sends client signals to the DOTS server, if and only if the DOTS server is
also sending server signals to the client in reaction to the client's signals.


### Relayed Signaling ###

A signaling session may also include one or more DOTS relays in the signaling
path between the clients and servers, as show in Figure N:

~~~~~
        +-------------+                            +-------------+
        | DOTS client |                            | DOTS server |
        +-------------+                            +-------------+
               ^                                         ^
               |            +---------------+            |
               \----------->| DOTS relay(s) |<-----------/
                            +---------------+
~~~~~

At its most basic, such a signaling session is logically identical to the
following, Figure N:

~~~~~
        +-------------+                            +-------------+
        | DOTS client |                            | DOTS server |
        +-------------+                            +-------------+
               ^                                         ^
               |    +-------------------------------+    |
               \--->| DOTS server |<->| DOTS client |<---/
                    +-------------------------------+
~~~~~

The DOTS relay receives DOTS client signals in the role of a DOTS server, and
relays the signals from the originating DOTS client to the DOTS server in the
role of a DOTS client.


### Redirected Signaling ###

In certain circumstances, a DOTS server may want to redirect a DOTS client to
an alternative DOTS server for a signaling session. Such circumstances include
but are not limited to:

* Maximum number of signaling sessions with clients has been reached;

* Mitigation capacity exhaustion in the Mitigator with which the
  specific DOTS server is communicating;

* Mitigator outage or other downtime, such as scheduled maintenance;

* Scheduled DOTS server maintenance;

* Scheduled modifications to the network path between DOTS server and DOTS
  client.

The DOTS architecture does not require the DOTS server to justify the decision
to redirect the signaling session to another DOTS server.

After sending a redirect signal over the signal channel to the DOTS client, the
DOTS server MAY cease sending server signals to the DOTS client at any point in
the timeframe allowed by the protocol. A redirecting DOTS server MUST cease
sending server signals to the DOTS client before reaching the end of that
timeframe.

The DOTS server MAY send redundant redirect signals in order to increase the
probability that the DOTS client receives them. The DOTS client MUST treat the
first redirect signal it receives from the DOTS server as authoritative, and
ignore any subsequent redirect signals from that DOTS server.

On receiving a redirection request from a DOTS server, the DOTS client MUST
terminate its end of the signaling session with the redirecting DOTS server
within the time frame defined by the protocol.

The DOTS client MAY subsequently establish a new session with the DOTS server to
which it was redirected, but is not required to do so. Local policy on DOTS
server redirection is left to DOTS client operators.

A basic redirected signaling session involves the following steps, as shown
in Figure N:

~~~~~
        +-------------+                            +---------------+
        |             |<-(1)-- signal session A -->|               |
        |             |                            |               |
        |             |<=(2)== REDIRECT to B ======|               |
        | DOTS client |                            | DOTS server A |
        |             |X-(4)-- signal session A -->|               |
        |             |                            |               |
        |             |X-(5)-- signal session A --X|               |
        +-------------+                            +---------------+
               ^
               |
              (3) signal session B
               |
               v
        +---------------+
        | DOTS server B |
        +---------------+
~~~~~

[AM: does this interaction need a best-effort ACK from the client?]

1. An existing signaling session exists between a DOTS client and DOTS server
   with address A. The signaling session was established as described in section
   n.m above, Establishing Signaling Session.

1. DOTS server A sends a server signal containing a REDIRECT over the signal
   channel to the DOTS client. The REDIRECT asks the client to migrate the
   signaling session to DOTS server B.

1. The DOTS client extracts the redirect target from the server signal, and
   checks its redirection policy. The redirection policy permits following
   redirection to DOTS server B. If the DOTS client does not already have a
   separate signaling session with the redirection target, the DOTS client
   initiates and establishes a signaling session with DOTS server B as described
   in section TBD above.

1. Having sent the REDIRECT signal to the DOTS client, DOTS server A ceases
   sending server signals, leaving the signal channel half-closed. [AM: should
   the DOTS server leave active any mitigations currently running on behalf of
   the client? It's entirely possible that DOTS server A & B are connected to
   the same Mitigator in e.g. the max client session limit case above]

1. Having processed the REDIRECT from DOTS Server A, the DOTS client ceases
   sending client signals to DOTS Server A. With both halves of the signaling
   session now closed, the signaling session between the DOTS client and DOTS
   server A is considered terminated.

[AM: should following go in security considerations?]

Due to the increased probability of inbound packet loss during a DDoS attack, it
is RECOMMENDED that DOTS servers avoid sending redirects during active attacks.
The method by which the DOTS server measures an active attack is not in scope,
but might include available metrics from the Mitigator and server signal
lossiness as reported in the client signal.


Components
----------

### DOTS client ###

### DOTS server ###

### DOTS relay ###


Obstacles
---------

TBD

Security Considerations         {#security-considerations}
=======================

TBD

Change Log
==========

