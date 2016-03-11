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
  RFC2782:
  RFC6763:


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

### Key Words ###

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.


### Definition of Terms ###

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
administrative domains -- for example, between an enterprise domain and
the domain of a third-party attack scrubbing service -- as well as to a single
administrative domain. DOTS is generally assumed to be most effective when
aiding coordination of attack response between two or more participating
network domains, but single domain scenarios are valuable in their own right,
as when aggregating intra-domain DOTS client signals for inter-domain
coordinated attack response.


Assumptions     {#assumptions}
-----------

This document makes the following assumptions:

* The network or networks in which DOTS is deployed are assumed to offer the
  required connectivity between DOTS agents and any intermediary network
  elements, but the architecture imposes no additional limitations on the form
  of connectivity.

* Congestion and resource exhaustion are intended outcomes of a DDoS attack.
  Some operators may utilize non-impacted paths or networks for DOTS, however,
  it should be assumed that, in the large majority of instances, conditions will
  be hostile and that DOTS must be able to function in all circumstances,
  including when the signaling path is significantly impaired.

* There is no universal DDoS attack scale threshold triggering a coordinated
  response across network administrative domains. A network domain
  administrator, or service or application owner may arbitrarily set attack
  scale threshold triggers, or manually send requests for mitigation.

* The mitigation capacity and/or capability of networks receiving requests for
  coordinated attack response is opaque to the network sending the request. The
  entity receiving the DOTS client signal may or may not have sufficient
  capacity or capability to filter any or all DDoS attack traffic directed at
  a target.

* DOTS client and server signals, as well as messages sent through the data
  channel, are sent across any transit networks with the same probability of
  delivery as any other traffic between the DOTS client network and the DOTS
  server network. Any encapsulation required for successful delivery is left
  untouched by transit network elements. DOTS server and DOTS client cannot
  assume any preferential treatment of DOTS signals.

* The architecture allows for, but does not assume, the presence of Quality of
  Service (QoS) policy agreements between DOTS-enabled peer networks or local
  QoS prioritization aimed at ensuring delivery of DOTS messages between DOTS
  agents. QoS is an operational consideration only, not a functional part of
  a DOTS architecture.

* There is no assumption that the signal channel and the data channel should
  terminate on the same server and these may be loosely coupled.


Architecture
============

DOTS enables a target that is under a Distributed Denial-of-Service (DDoS)
attack to signal another entity for help in mitigating the DDoS attack. The
basic high-level DOTS architecture is illustrated in Figure X1


~~~~~
    +-----------+            +-------------+
    | Mitigator | ~~~~~~~~~~ | DOTS Server |
    +-----------+            +-------------+
                               |         |
                               |         |
                               |         |
                               |    +------------+
                               |    | DOTS Relay |
                               |    +------------+
                               |         |
                               |         |
                               |         |
   +---------------+         +-------------+
   | Attack Target | ~~~~~~~ | DOTS Client |
   +---------------+         +-------------+
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

The scope of the DOTS specifications is the interfaces between the DOTS
client, DOTS server, and DOTS relay. The interfaces to the attack target and
the mitigator are out of scope of DOTS. Similarly, the operation of both the
attack target and the mitigator are out of scope of DOTS. Thus, DOTS neither
specifies how an attack target decides it is under DDoS attack, nor does DOTS
specify how a mitigator may actually mitigate such an attack. Indeed, a DOTS
client's request for mitigation is advisory in nature, and may not lead to any
mitigation at all, depending on the DOTS server entity's capacity and
willingness to mitigate on behalf of the DOTS client's entity.

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
request. Assuming it will, the DOTS Server initiates attack mitigation (by means
outside of DOTS), and periodically informs the DOTS client about the status of
the mitigation.  Similarly, the DOTS client periodically informs the DOTS server
about the client's status, which at a minimum provides client (attack target)
health information, but it may also include telemetry information about the
attack as it is now seen by the client. At some point, the DOTS client or the
DOTS server may decide to terminate the server-side attack mitigation, which it
indicates to the DOTS peer agent (DOTS client or server) over the signal
channel. Note that the signal channel may need to operate over a link that is
experiencing a DDoS attack and hence is subject to very severe packet loss.

While DOTS is able to function with just the signal channel, the addition of
the DOTS data channel provides for additional and more efficient capabilities.
The primary purpose of the data channel is to support DOTS related
configuration and policy information exchange between the DOTS client and
the DOTS server. Examples of such information include

* Defining names or aliases for attack targets (resources). Those names can be
  used in subsequent signal channel exchanges to more efficiently refer to the
  resources (attack targets) in question.

* Black-list management, which enables a DOTS client to inform the DOTS server
  about sources to suppress.

* White-list management, which enables a DOTS client to inform the DOTS server
  about sources from which traffic should always be accepted.

Note that while it is possible to exchange the above information before, during
or after a DDoS attack, DOTS requires reliable delivery of the above
information and does not provide any special means for ensuring timely delivery
of it during an attack. In practice, this means that DOTS entities SHOULD NOT
rely on such information being exchanged during a DDoS attack.


DOTS Operations
---------------
The scope of DOTS is focused on the signaling and data exchange between the DOTS
client, DOTS server and (possibly) the DOTS relay. DOTS does not prescribe any
specific deployment models, however DOTS is designed with some specific
requirements around the different DOTS agents and their relationships.

First of all, a DOTS agent belongs to an entity, and that entity has an identity
which can be authenticated. DOTS agents communicate with each other over a
mutually authenticated signal channel. However, before they can do so, a service
relationship needs to be established between them.  The details and means by
which this is done is outside the scope of DOTS, however an example would be for
an enterprise A (DOTS client) to sign up for DDoS service from provider B (DOTS
server). This would establish a (service) relationship between the two that
enables enterprise A's DOTS client to establish a signal channel with provider
B's DOTS server. A and B will authenticate each other, and B can verify that A
is authorized for its service. A and B may each have one or more DOTS relays in
front of their DOTS client and DOTS server. Considerations of end-to-end
signaling and agent authentication with relays in the signaling path are
discussed below.

From an operational and design point of view, DOTS assumes that the above
relationship is established prior to a request for DDoS attack mitigation. In
particular, it is assumed that bi-directional communication is possible at this
time between the DOTS client and DOTS server. Furthermore, it as assumed that
additional service provisioning and information exchange can be performed by use
of the data channel, if so desired. It is not until this point that the
mitigation service is available for use.

Once the mutually authenticated signal channel has been established, it will
remain in place. This is done to increase the likelihood that the DOTS client
can signal the DOTS server for help when the the attack target is being flooded,
and similarly raise the probability that DOTS server signals reach the client
regardless of inbound link congestion.  This does not necessarily imply that the
attack target and the DOTS client have to be co-located, but it is expected to
be a common scenario.

DDoS mitigation service with the help of an upstream mitigator will often
involve some form of traffic redirection whereby traffic destined for the attack
target is diverted towards the mitigator, e.g. by use of BGP or DNS. The
mitigator in turn inspects and scrubs the traffic, and forwards the resulting
(hopefully non-attack) traffic to the attack target, e.g. via a GRE tunnel.
Thus, when a DOTS server receives an attack mitigation request from a DOTS
client, it can be viewed as a way of causing traffic redirection for the attack
target indicated. Note that DOTS does not consider any authorization aspects
around who should be allowed to issue such requests for what attack targets.
Instead, DOTS merely relies on the mutual authentication and the pre-established
(service) relationship between the entity owning the DOTS client and the entity
owning the DOTS server. The entity owning the DOTS server may consider limiting
the attack targets that a particular DOTS client can request mitigation for as
part of establishing this relationship.


DOTS Agent Relationships
------------------------

So far, we have only considered a relatively simple scenario of a
single DOTS client associated with a single DOTS server, however DOTS
supports more advanced relationships as follows:

A DOTS server may be associated with one or more DOTS clients, and
those DOTS clients may belong to different entities.  An example
scenario is a mitigation provider serving multiple attack targets.

~~~~~
   +---+
   | c |-----------
   +---+           \
                    \
   +---+             \ +---+
   | c |---------------| S |
   +---+             / +---+
                    /
   +---+           /
   | c |-----------
   +---+
   example.com/.org   example.net
   DOTS Clients       DOTS Server
~~~~~

A DOTS client may be associated with one or more DOTS servers, and
those DOTS servers may belong to different entities.  This may be to ensure
high availability or co-ordinate mitigation with more than one directly
connected ISP.  An example scenario is for an enterprise to have DDoS
mitigation service from multiple providers.  Operational considerations
relating to co-ordinating multiple provider responses are beyond the scope of
DOTS.

~~~~~
                       +---+
           ------------| S |
          /            +---+
         /
   +---+/              +---+
   | c |---------------| S |
   +---+\              +---+
         \
          \            +---+
           ------------| S |
                       +---+
   example.com        example.net/.org
   DOTS Client        DOTS Servers
~~~~~

DOTS Relays may be either server-side or client-side.  A DOTS server side
relay is associated with the same entity.  A relay will terminate multiple
discrete client connections as if it were a server and may aggregate these
into a single or multiple DOTS feeds depending upon locally applied policy.
A relay will function as a server to its downstream clients and as a client
to its upstream peers.  The relationship between the relay and its upstream
peers is opaque to the relayed clients.An example scenario is for an
enterprise to have deployed multiple DOTS capable devices which are able to
signal intra-domain using TCP on un-congested links to a relay which may then
transform these to a UDP transport inter-domain where connection oriented
transports may degrade.  The relationship between the relay and its upstream
peers is opaque to the relayed clients.

~~~~~
   Client Side Relay (incl. aggregation)

   +---+
   | c |\
   +---+ \              +---+
          \-----TCP-----| r |              +---+
   +---+                | e |              |   |
   | c |--------TCP-----| l |------UDP-----| S |
   +---+                | a |              |   |
          /-----TCP-----| y |              +---+
   +---+ /              +---+
   | c |/
   +---+
   example.com       example.com         example.net
   DOTS Clients      DOTS Relay          DOTS Server
~~~~~

~~~~~
   Client Side Relay (excl. aggregation)

   +---+
   | c |\
   +---+ \              +---+
          \-----TCP-----| r |------UDP-----+---+
   +---+                | e |              |   |
   | c |--------TCP-----| l |------UDP-----| S |
   +---+                | a |              |   |
          /-----TCP-----| y |------UDP-----+---+
   +---+ /              +---+
   | c |/
   +---+
   example.com       example.com         example.net
   DOTS Clients      DOTS Relay          DOTS Server
~~~~~

A variation of this scenario would be a DDoS mitigation provider deploying
relays at their perimeter to consume signals across multiple transports and
to consolidate these into a single transport suitable for the providers
deployment.  The relationship between the relay and its upstream peers is
opaque to the relayed clients.

~~~~~
   Server Side Relay (incl aggregation)

   +---+
   | c |\
   +---+ \              +---+
          \-----UDP-----| r |              +---+
   +---+                | e |              |   |
   | c |--------TCP-----| l |------TCP-----| S |
   +---+                | a |              |   |
          /----SCTP-----| y |              +---+
   +---+ /              +---+
   | c |/
   +---+
   example.com       example.net         example.net
   DOTS Clients      DOTS Relay          DOTS Server
~~~~~

~~~~~
   Server Side Relay (excl aggregation)

   +---+
   | c |\
   +---+ \              +---+
          \-----UDP-----| r |------TCP-----+---+
   +---+                | e |              |   |
   | c |--------TCP-----| l |------TCP-----| S |
   +---+                | a |              |   |
          /----SCTP-----| y |------TCP-----+---+
   +---+ /              +---+
   | c |/
   +---+
   example.com       example.net         example.net
   DOTS Clients      DOTS Relay          DOTS Server
~~~~~

In the context of relays, sessions are established between elements and may
not be end to end.  In spite of this distinction a method must exist to
uniquely identify the originating DOTS client. The relay should identify
itself as such to any clients or servers it interacts with.  Greater
abstraction by way of additional layers of relays may introduce undesired
complexity in regard to authentication and authorization and should be
avoided.


Components
==========

The architecture in this document is comprised of a few basic components on top
of the assumed underlay network or networks described above. When connected to
one another, the components represent an operational DOTS architecture.

This section describes the components themselves. Section N.N below describes
the architectural concepts involved.


DOTS client
-----------

A DOTS client is a DOTS agent from which requests for help coordinating attack
response originate. The requests may be in response to an active, ongoing
attack against a target in the DOTS client's domain, but no active attack is
required for a DOTS client to request help. Local operators may wish to
have upstream traffic scrubbers in the network path for an indefinite period,
and are restricted only by business relationships when it comes to duration
and scope of requested mitigation.

The DOTS client requests attack response coordination from a DOTS server over
the signal channel, including in the request the DOTS client's desired
mitigation scoping, as described in [I-D.ietf-dots-requirements], and suggested
countermeasures. The actual mitigation scope and countermeasures used in
response to the attack are up to the DOTS server and Mitgator operators, as the
DOTS client may have a narrow perspective on the ongoing attack. As such, the
DOTS client's request for mitigation should be considered advisory: guarantees
of DOTS server availability or mitigation capacity constitute service level
agreements and are out of scope for this document.

The DOTS client adjusts mitigation scope and suggested countermeasures at the
direction of its local operator. Such direction may involve manual or automated
adjustments in response to feedback from the DOTS server.

To provide a metric of signal health and distinguish an idle signaling session
from a disconnected or defunct session, the DOTS client sends a heartbeat over
the signal channel to maintain its half of the signaling session. The DOTS
client similarly expects a heartbeat from the DOTS server, and MAY consider a
signaling session terminated in the extended absence of a DOTS server heartbeat.

TBD


DOTS server
-----------

TBD


Concepts
========

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


### Preconditions ###

Prior to establishing a signaling session between agents, the owners of the
networks, domains, services or applications involved are assumed to have agreed
upon the terms of the relationship involved. Such agreements are out of scope
for this document, but must be in place for a functional DOTS architecture.

It is assumed that as part of any DOTS service agreement, the DOTS client is
provided with all data and metadata required to establish communication with the
DOTS server. Such data and metadata would include any cryptographic information
necessary to meet the message confidentiality, integrity and authenticity
requirement in [I-D.ietf-dots-requirements], and might also include the pool of
DOTS server addresses and ports the DOTS client should use for signal and data
channel messaging.


### Establishing the Signaling Session ###

With the required business or service agreements in place, the DOTS client
initiates a signal session by contacting the DOTS server. The DOTS server's
address may have been provided during provisioning of the DOTS client, but the
architecture leaves open the possibility that the DOTS client may discover one
or more available DOTS servers through such methods as DNS SRV {{RFC2782}} or
DNS Service Discovery {{RFC6763}}.

The DOTS client's initial message to the DOTS server is over the data channel.
Using data channel semantics established in the DOTS protocol, the DOTS client
learns the address of the DOTS server with which to establish a signal channel,
which may or may not be the same as the DOTS server operating the data channel,
as well as any additional DOTS servers with which it should establish signaling
sessions. The DOTS server MAY redirect to a different DOTS server at this point.

Assuming the DOTS server authenticates the DOTS client, the DOTS client MAY at
this time adjust initial configuration, including black- and white-listed
prefixes or addresses.

Using the signal channel information learned from the data channel request, the
DOTS client contacts the DOTS server over the signal channel. Once the DOTS
client begins receiving DOTS server signals, the signaling session is
active.


### Maintaining the Signaling Session ###

The DOTS client and server periodically send heartbeats to each other over the
signal channel. The period of these heartbeats will be established by the
protocol definition, but should be in a range allowing for reasonably rapid
detection of a degraded signal channel to aid operator response to an ongoing
DDoS attack, with low enough frequency to prevent accidental denials of service
incurred by overwhelming a DOTS server with heartbeat messages.

Either DOTS agent may consider a signaling session terminated in the extended
absence of a heartbeat from its peer agent. The period of that absence will be
established in the protocol definition.


### Direct Signaling ###

A signaling session may take the form of direct signaling between the DOTS
clients and servers, as shown in Figure N below:

~~~~~
        +-------------+                            +-------------+
        | DOTS client |<------signal channel------>| DOTS server |
        +-------------+                            +-------------+
~~~~~

In a direct signaling session, DOTS client and server are communicating
directly, with no relays in the signaling path. A direct signaling session may
exist inter- or intra-domain; the signaling session is abstracted from the
underlying networks or network elements the signals traverse.


### Relayed Signaling ###

A signaling session may also include one or more DOTS relays in the signaling
path between the clients and servers, as shown in Figure N:

~~~~~
        +-------------+                            +-------------+
        | DOTS client |                            | DOTS server |
        +-------------+                            +-------------+
               ^                                         ^
               |            +---------------+            |
               \----------->| DOTS relay(s) |<-----------/
                            +---------------+
~~~~~



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
        |             |<-(1)-- signal session 1 -->|               |
        |             |                            |               |
        |             |<=(2)== redirect to B ======|               |
        | DOTS client |                            | DOTS server A |
        |             |X-(4)-- signal session 1 --X|               |
        |             |                            |               |
        |             |                            |               |
        +-------------+                            +---------------+
               ^
               |
              (3) signal session 2
               |
               v
        +---------------+
        | DOTS server B |
        +---------------+
~~~~~

1. Previously established signaling session 1 exists between a DOTS client and
   DOTS server with address A.

1. DOTS server A sends a server signal redirecting the client to DOTS server B.

1. If the DOTS client does not already have a separate signaling session with
   the redirection target, the DOTS client initiates and establishes a signaling
   session with DOTS server B as described above. The DOTS client MAY request
   mitigation via DOTS server B as soon as signal session 1 is established.

1. Having redirected the DOTS client, DOTS server A ceases sending server
   signals. The DOTS client likewise stops sending client signals to DOTS server
   A. Signal session 1 is terminated, severing any attack response coordination
   with DOTS server A.

Following signaling session termination, the DOTS server SHOULD tear down
mitigations activated on behalf of the DOTS client, though operational
relationships between the redirecting and redirection target DOTS servers should
be taken into account before doing so, given that the two DOTS servers may
belong to the same entity, and indeed may be using the same mitigator to scrub
attack traffic.

Due to the increased probability of inbound packet loss during a DDoS attack, it
is RECOMMENDED that DOTS servers avoid sending redirects during active attacks.
The method by which the DOTS server measures an active attack is not in scope,
but is assumed include available metrics from the Mitigator and server signal
lossiness as reported in the client signal.


Security Considerations         {#security-considerations}
=======================

TBD

Change Log
==========

