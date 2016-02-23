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
administrative domains -- for example, between an enterprise domain and
the domain of a third-party attack scrubbing service -- as well as to a single
administrative domain. DOTS is generally assumed to be most effective when
aiding coordination of attack response between two or more participating
network domains, but single domain scenarios are worth investigating elsewhere. [**FSA**: What do we mean by "elsewhere" ?}


Assumptions     {#assumptions}
-----------

This document makes the following assumptions:
[NT: rough but growing list]

* The existence of agreed DOTS data model(s) and protocol definitions.[**FSA**: Not sure I follow - why is this an assumption ?]

* The network or networks in which DOTS is deployed are assumed to offer the
  required connectivity between DOTS agents and any intermediary network
  elements, but the architecture imposes no additional limitations on the form
  of connectivity.

* Congestion and resource exhaustion are intended outcomes of a DDoS attack.
  Some operators may utilize non-impacted paths or networks for DOTS, however,
  it should be assumed that, in the large majority of instances, conditions will
  be hostile and that signaling SHOULD function in all circumstances.[**FSA**: Maybe rephrase to "that DOTS must be able to function in all circumstances, including when the signaling path is significantly impaired"

* There is no universal DDoS attack scale threshold triggering a coordinated
  response across network administrative domains. A network domain
  administrator, or service or application owner may arbitrarily set attack
  scale threshold triggers, or manually send requests for mitigation.

* The mitigation capacity and/or capability of networks receiving requests for
  coordinated attack response is opaque to the network sending the request. The
  network receiving the DOTS client signal may or may not have sufficient
  capacity or capability to filter any or all DDoS attack traffic directed at
  a target.[**FSA**: The term "network" is too restrictive - we need another term to use throughout]

* DOTS client and server signals, as well as messages sent through the data
  channel, are sent across any transit networks with the same probability of
  delivery as any other traffic between the DOTS client network and the DOTS
  server network. Any encapsulation required for successful delivery is left
  untouched by transit network elements.[**FSA**: Maybe re-write this one to say something like "cannot assume any preferential treatment...", since the next one does open up the door for higher probability delivery]

* The architecture allows for, but does not assume, the presence of Quality of
  Service (QoS) policy agreements between DOTS-enabled peer networks or local
  QoS prioritization aimed at ensuring delivery of DOTS signals between DOTS
  agents.[**FSA**: Only DOTS signals or also DOTS data ?]

* There is no assumption that the signal channel and the data channel should
  terminate on the same server and these may be loosely coupled.
  [NT: Redirection may occur within the signal channel but the data channel
  should also allocate signaller and default to the same server if not present?][**FSA**: Not sure I understand the question]


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
speficies how an attack target decides it is under DDoS attack, nor does DOTS
specify how a mitigator may actually mitigate such an attack.

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
request. Assuming it will, the DOTS Server initiates attack mitigation (by means outside of DOTS), and
periodically informs the DOTS client about the status of the mitigation.
Similarly, the DOTS client periodically informs the DOTS server about the
client's status, which at a minimum provides client (attack target) health
information, but it may also include telemetry information about the attack as
it is now seen by the client. At some point, the DOTS client or the DOTS server may
decide to terminate the server-side attack mitigation, which it indicates to
the DOTS peer agent (DOTS client or server) over the signal channel. Note that
the signal channel may need to operate over a link that is experiencing a DDoS
attack and hence is subject to very severe packet loss.

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

* White-list, which enables a DOTS client to inform the DOTS server about
  sources that should always be accepted.

Note that while it is possible to exchange the above information before, during
or after a DDoS attack, DOTS requires reliable delivery of the above
information and does not provide any special means for ensuring timely delivery
of it during an attack. In practice, this means that DOTS entities SHOULD NOT
rely on such information being exchanged during a DDoS attack.


DOTS Operations 
---------------
The scope of DOTS is focused on the signaling and data exchange
between the DOTS client, DOTS server and (possibly) the DOTS relay. DOTS does not prescribe any specific deployment models, however DOTS is designed with some specific requirements around the different DOTS agents and their relationships.

First of all, a DOTS agent belongs to an entity, and that entity has an identity which can be authenticated. DOTS agents communicate with each other over a mutually authenticated signal channel, however before they can do so, a service relationship needs to be established between them.  The details and means by which this is done is outside the scope of DOTS, however an example would be for an enterprise A (DOTS client) to sign up for DDoS service from provider B (DOTS server). This would establish a (service) relationship between the two that enables enterprise A's DOTS client to establish a signal channel with provider B's DOTS server. A and B will authenticate each other, and B can verify that A is authorized for its service. A and B may each have one or more DOTS relays in front of their DOTS client and DOTS server [**FSA**: *I don't recall what we said here in terms of e2e connectivitiy and authentication*]. 

From an operational and design point of view, DOTS assumes that the above relationship is established prior to a request for DDoS attack mitigation. In particular, it is assumed that bi-directional communication is possible at this time between the DOTS client and DOTS server. Furthermore, it as assumed that additional service provisioning and information exchange can be performed by use of the data channel, if so desired. It is not until this point that the mitigation service is available for use. 

Once the mutually authenticated signal channel has been established, it will remain in place. This is done to increase the likelihood that the DOTS client can signal the DOTS server for help when the the attack target is being flooded. This does not necessarily imply that the attack target and the DOTS client have to be co-located, but it is expected to be a common scenario. 

DDoS mitigiation service with the help of an upstream mitigator will often involve some form of traffic redirection whereby traffic destined for the attack target is diverted towards the mitigator, e.g. by use of BGP or DNS. The mitigator in turn inspects and scrubs the traffic, and forwards the resulting (hopefully non-attack) traffic to the attack target, e.g. via a GRE tunnel. Thus, when a DOTS server receives an attack mitigation request from a DOTS client, it can be viewed as a way of causing traffic redirection for the attack target indicated. Note that DOTS does not consider any authorization aspects around who should be allowed to issue such requests for what attack targets. Instead, DOTS merely relies on the mutual authentication and the pre-established (service) relationship between the entity owning the DOTS client and the entity owning the DOTS server. The entity owning the DOTS server may consider limiting the attack targets that a particular DOTS client can request mitigation for as part of establising this relationship. 


DOTS Agent Relationships
------------------------
So far, we have only considered a relatively simple scenario of a single DOTS client associated with a single DOTS server, however DOTS supports more advanced relationships as follows: 

A DOTS server may be associated with one or more DOTS clients, and those DOTS clients may belong to different entities. An example scenario is a mitigation provider serving multiple attack targets.

A DOTS client may be associated with one or more DOTS servers, and those DOTS servers may belong to different entities. An example scenario is for an enterprise to have DDoS mitigation service from multiple providers. [**FSA**: *I don't remember if we said that the client should be able to ask for mitigation for a given attack target from different entities - discuss again*]

[**FSA**: *When talking about DOTS relays, I'm finding a need to distinguish between server-side relays and client-side relays - or at least I think so....*]

DOTS Relays may be either server-side or client-side. A DOTS server-side relay is associated with the same entity 

[**FSA**: *I need some more text from somebody on how these DOTS relays actually work and how the work on the client side, server side and in-between (if there is something like that) - I'm having DIAMETER flashbacks here and I'm not liking it.....*] 



[**FSA**: Old for discussion
* A DOTS Client is associated with one or more DOTS Servers (?)

* A DOTS Client is associated with one or more DOTS Relays (?)

* A DOTS Relay is assocaited with one or more DOTS Clients

* A DOTS Relay is associated with one or more DOTS Servers

* A DOTS Relay is associated with one or more DOTS Relays (graph/hierarchy ?)

* A DOTS Relay logically consists of a DOTS Server and a DOTS Client (?)

* Can a DOTS Client tell if it is talking to a DOTS Server or a DOTS Relay ?

* Can a DOTS Server tell if it is talking to a DOTS Client or a DOTS Relay ?]


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
[**FSA**: I think we are beginning to get into protocol specification territory with some of this - need to determine where we draw the line]

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

