---
title: Distributed-Denial-of-Service Open Threat Signaling (DOTS) Architecture
abbrev: DOTS Architecture
docname: draft-ietf-dots-architecture-00
date: @DATE@

area: Security
wg: DOTS
kw: Internet-Draft
cat: info

coding: us-ascii
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  docmapping: yes

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
        ins: T. Reddy
        name: Tirumaleswar Reddy
        org: Cisco Systems, Inc.
        street:
        - Cessna Business Park, Varthur Hobli
        - Sarjapur Marathalli Outer Ring Road
        city: Bangalore, Karnataka
        code: 560103
        country: India
        email: tireddy@cisco.com
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
        ins: R. Compton
        name: Rich Compton
        org: Charter Communications, Inc.
        street:
        -
        city:
        -
        code:
        -
        email: Rich.Compton@charter.com
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
  RFC0768:
  RFC0793:
  RFC1034:
  RFC2782:
  RFC3261:
  RFC4271:
  RFC4732:
  RFC6763:
  RFC7092:


--- abstract

This document describes an architecture for establishing and maintaining
Distributed Denial of Service (DDoS) Open Threat Signaling (DOTS) within and
between domains. The document does not specify protocols or protocol
extensions, instead focusing on defining architectural relationships, components
and concepts used in a DOTS deployment.


--- middle

Context and Motivation {#context-and-motivation}
======================

Signaling the need for help defending against an active distributed denial
of service (DDoS) attack requires a common understanding of mechanisms and
roles among the parties coordinating defensive response. The signaling
layer and supplementary messaging is the focus of DDoS Open Threat Signaling
(DOTS). DOTS defines a method of coordinating defensive measures among willing
peers to mitigate attacks quickly and efficiently, enabling hybrid attack
responses coordinated locally at or near the target of an active attack, or
anywhere in-path between attack sources and target.

This document describes an architecture used in establishing, maintaining or
terminating a DOTS relationship within a domain or between domains.


Terminology     {#terminology}
-----------

### Key Words ###

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.


### Definition of Terms ###

This document uses the terms defined in [I-D.ietf-dots-requirements].


Scope           {#scope}
-----

In this architecture, DOTS clients and servers communicate using the DOTS
signaling. As a result of signals from a DOTS client, the DOTS server may modify
the forwarding path of traffic destined for the attack target(s), for example by
diverting traffic to a mitigator or pool of mitigators, where policy may be
applied to distinguish and discard attack traffic. Any such policy is
deployment-specific.

The DOTS architecture presented here is applicable across network administrative
domains -- for example, between an enterprise domain and the domain of a
third-party attack mitigation service -- as well as to a single administrative
domain. DOTS is generally assumed to be most effective when aiding coordination
of attack response between two or more participating network domains, but single
domain scenarios are valuable in their own right, as when aggregating
intra-domain DOTS client signals for inter-domain coordinated attack response.


This document does not address any administrative or business agreements that
may be established between involved DOTS parties. Those considerations are out
of scope. Regardless, this document assumes necessary authentication and
authorization mechanism are put in place so that only authorized clients can
invoke the DOTS service.


Assumptions     {#assumptions}
-----------

This document makes the following assumptions:

* All domains in which DOTS is deployed are assumed to offer the required
  connectivity between DOTS agents and any intermediary network elements, but
  the architecture imposes no additional limitations on the form of
  connectivity.

* Congestion and resource exhaustion are intended outcomes of a DDoS attack
  {{RFC4732}}. Some operators may utilize non-impacted paths or networks for
  DOTS, but in general conditions should be assumed to be hostile and that DOTS
  must be able to function in all circumstances, including when the signaling
  path is significantly impaired.

* There is no universal DDoS attack scale threshold triggering a coordinated
  response across administrative domains. A network domain administrator, or
  service or application owner may arbitrarily set attack scale threshold
  triggers, or manually send requests for mitigation.

* Mitigation requests may be sent to one or more upstream DOTS servers based on
  criteria determined by DOTS client administrators. The number of DOTS servers
  with which a given DOTS client has established signaling sessions is
  determined by local policy and is deployment-specific.

* The mitigation capacity and/or capability of domains receiving requests for
  coordinated attack response is opaque to the domains sending the request. The
  entity receiving the DOTS client signal may or may not have sufficient
  capacity or capability to filter any or all DDoS attack traffic directed at
  a target. In either case, the upstream DOTS server may redirect a request to
  another DOTS server. Redirection may be local to the redirecting DOTS server's
  domain, or may involve a third-party domain.

* DOTS client and server signals, as well as messages sent through the data
  channel, are sent across any transit networks with the same probability of
  delivery as any other traffic between the DOTS client domain and the DOTS
  server domain. Any encapsulation required for successful delivery is left
  untouched by transit network elements. DOTS server and DOTS client cannot
  assume any preferential treatment of DOTS signals. Such preferential treatment
  may be available in some deployments, and the DOTS architecture does not
  preclude its use when available. However, DOTS itself does not address how
  that may be done.

* The architecture allows for, but does not assume, the presence of Quality of
  Service (QoS) policy agreements between DOTS-enabled peer networks or local
  QoS prioritization aimed at ensuring delivery of DOTS messages between DOTS
  agents. QoS is an operational consideration only, not a functional part of
  the DOTS architecture.

* The signal channel and the data channel may be loosely coupled, and need not
  terminate on the same DOTS server.


Architecture {#architecture}
============

The basic high-level DOTS architecture is illustrated in {{fig-basic-arch}}:

~~~~~
    +-----------+            +-------------+
    | Mitigator | ~~~~~~~~~~ | DOTS Server |
    +-----------+            +-------------+
                                    |
                                    |
                                    |
    +---------------+        +-------------+
    | Attack Target | ~~~~~~ | DOTS Client |
    +---------------+        +-------------+
~~~~~
{: #fig-basic-arch title="Basic DOTS Architecture"}

A simple example instantiation of the DOTS architecture could be an enterprise
as the attack target for a volumetric DDoS attack, and an upstream DDoS
mitigation service as the Mitigator. The enterprise (attack target) is
connected to the Internet via a link that is getting saturated, and the
enterprise suspects it is under DDoS attack. The enterprise has a DOTS client,
which obtains information about the DDoS attack, and signals the DOTS server
for help in mitigating the attack. The DOTS server in turn invokes one or more
mitigators, which are tasked with mitigating the actual DDoS attack, and hence
aim to suppress the attack traffic while allowing valid traffic to reach the
attack target.

The scope of the DOTS specifications is the interfaces between the DOTS
client and DOTS server. The interfaces to the attack target and the mitigator
are out of scope of DOTS. Similarly, the operation of both the attack target and
the mitigator are out of scope of DOTS. Thus, DOTS neither specifies how an
attack target decides it is under DDoS attack, nor does DOTS specify how a
mitigator may actually mitigate such an attack. A DOTS client's request for
mitigation is advisory in nature, and may not lead to any mitigation at all,
depending on the DOTS server entity's capacity and willingness to mitigate on
behalf of the DOTS client's entity.

As illustrated in {{fig-interfaces}}, there are two interfaces between the
DOTS server and the DOTS client:

~~~~~
    +---------------+                                 +---------------+
    |               | <------- Signal Channel ------> |               |
    |  DOTS Client  |                                 |  DOTS Server  |
    |               | <=======  Data Channel  ======> |               |
    +---------------+                                 +---------------+
~~~~~
{: #fig-interfaces title="DOTS Interfaces"}

The DOTS client may be provided with a list of DOTS servers, each associated
with one or more IP addresses. These addresses may or may not be of the same
address family. The DOTS client establishes one or more signaling sessions by
connecting to the provided DOTS server addresses.

\[\[EDITOR'S NOTE: We request feedback from the working group about the mechanism
of server discovery.\]\]

The primary purpose of the signal channel is for a DOTS client to ask a
DOTS server for help in mitigating an attack, and for the DOTS server to inform
the DOTS client about the status of such mitigation. The DOTS client does this
by sending a client signal, which contains information about the attack target
or targets.  The client signal may also include telemetry information about the
attack, if the DOTS client has such information available. The DOTS server in
turn sends a server signal to inform the DOTS client of whether it will honor
the mitigation request. Assuming it will, the DOTS server initiates attack
mitigation (by means outside of DOTS), and periodically informs the DOTS client
about the status of the mitigation.  Similarly, the DOTS client periodically
informs the DOTS server about the client's status, which at a minimum provides
client (attack target) health information, but it may also include telemetry
information about the attack as it is now seen by the client. At some point, the
DOTS client may decide to terminate the server-side attack mitigation, which it
indicates to the DOTS server over the signal channel. A mitigation may also be
terminated if a DOTS client-specified mitigation time limit is exceeded;
additional considerations around mitigation time limits may be found below. Note
that the signal channel may need to operate over a link that is experiencing a
DDoS attack and hence is subject to severe packet loss and high latency.

While DOTS is able to request mitigation with just the signal channel, the
addition of the DOTS data channel provides for additional and more efficient
capabilities; both channels are required in the DOTS architecture. The primary
purpose of the data channel is to support DOTS related configuration and policy
information exchange between the DOTS client and the DOTS server. Examples of
such information include, but are not limited to:

* Creating identifiers, such as names or aliases, for resources for which
  mitigation may be requested. Such identifiers may then be used in subsequent
  signal channel exchanges to refer more efficiently to the resources under
  attack, as seen in {{fig-resource-identifiers}} below, using JSON to serialize
  the data:

~~~~~
        {
            "https1": [
                "172.16.168.254:443",
                "172.16.169.254:443",
            ],
            "proxies": [
                "10.0.0.10:3128",
                "[2001:db9::1/128]:3128"
            ],
            "api_urls": "https://apiserver.local/api/v1",
        }
~~~~~
{: #fig-resource-identifiers title="Protected resource identifiers"}

* Black-list management, which enables a DOTS client to inform the DOTS server
  about sources to suppress.

* White-list management, which enables a DOTS client to inform the DOTS server
  about sources from which traffic should always be accepted.

* Filter management, which enables a DOTS client to install or remove traffic
  filters dropping or rate-limiting unwanted traffic.

* DOTS client provisioning.

Note that while it is possible to exchange the above information before, during
or after a DDoS attack, DOTS requires reliable delivery of the this information
and does not provide any special means for ensuring timely delivery of it during
an attack. In practice, this means that DOTS entities SHOULD NOT rely on such
information being exchanged during a DDoS attack.


DOTS Operations {#operations}
---------------
The scope of DOTS is focused on the signaling and data exchange between the DOTS
client and DOTS server. DOTS does not prescribe any specific deployment models,
however DOTS is designed with some specific requirements around the different
DOTS agents and their relationships.

First of all, a DOTS agent belongs to an entity, and that entity has an identity
which can be authenticated and authorized. DOTS agents communicate with each
other over a mutually authenticated signal channel and data channel. However,
before they can do so, a service relationship needs to be established between
them.  The details and means by which this is done is outside the scope of DOTS,
however an example would be for an enterprise A (DOTS client) to sign up for
DDoS service from provider B (DOTS server). This would establish a (service)
relationship between the two that enables enterprise A's DOTS client to
establish a signal channel with provider B's DOTS server. A and B will
authenticate each other, and B can verify that A is authorized for its service.

From an operational and design point of view, DOTS assumes that the above
relationship is established prior to a request for DDoS attack mitigation. In
particular, it is assumed that bi-directional communication is possible at this
time between the DOTS client and DOTS server. Furthermore, it is assumed that
additional service provisioning, configuration and information exchange can be
performed by use of the data channel, if operationally required. It is not until
this point that the mitigation service is available for use.

Once the mutually authenticated signal channel has been established, it will
remain in place. This is done to increase the likelihood that the DOTS client
can signal the DOTS server for help when the attack target is being flooded,
and similarly raise the probability that DOTS server signals reach the client
regardless of inbound link congestion.  This does not necessarily imply that the
attack target and the DOTS client have to be co-located in the same
administrative domain, but it is expected to be a common scenario.

DDoS mitigation service with the help of an upstream mitigator will often
involve some form of traffic redirection whereby traffic destined for the attack
target is diverted towards the mitigator, e.g. by use of BGP [RFC4271] or DNS
[RFC1034]. The mitigator in turn inspects and scrubs the traffic, and forwards
the resulting (hopefully non-attack) traffic to the attack target. Thus, when a
DOTS server receives an attack mitigation request from a DOTS client, it can be
viewed as a way of causing traffic redirection for the attack target indicated.
Note that the DOTS specifications do not address any authorization aspects
around who should be allowed to issue such requests for what attack targets.
Instead, DOTS merely relies on the mutual authentication and the pre-established
(service) relationship between the entity owning the DOTS client and the entity
owning the DOTS server. The entity owning the DOTS server SHOULD limit the
attack targets that a particular DOTS client can request mitigation for as part
of establishing this relationship. The method of such limitation is not in scope
for this document.

Although co-location of DOTS server and mitigator within the same entity is
expected to be a common deployment model, it is assumed that operators may
require alternative models. Nothing in this document precludes such
alternatives.


Components
----------

### DOTS Client {#dots-client}

A DOTS client is a DOTS agent from which requests for help coordinating attack
response originate. The requests may be in response to an active, ongoing
attack against a target in the DOTS client's domain, but no active attack is
required for a DOTS client to request help. Local operators may wish to
have upstream mitigators in the network path for an indefinite period, and are
restricted only by business relationships when it comes to duration and scope of
requested mitigation.

The DOTS client requests attack response coordination from a DOTS server over
the signal channel, including in the request the DOTS client's desired
mitigation scoping, as described in [I-D.ietf-dots-requirements]. The actual
mitigation scope and countermeasures used in response to the attack are up to
the DOTS server and Mitigator operators, as the DOTS client may have a narrow
perspective on the ongoing attack. As such, the DOTS client's request for
mitigation should be considered advisory: guarantees of DOTS server availability
or mitigation capacity constitute service level agreements and are out of scope
for this document.

The DOTS client adjusts mitigation scope and provides available attack details
at the direction of its local operator. Such direction may involve manual or
automated adjustments in response to feedback from the DOTS server.

To provide a metric of signal health and distinguish an idle signaling session
from a disconnected or defunct session, the DOTS client sends a heartbeat over
the signal channel to maintain its half of the signaling session. The DOTS
client similarly expects a heartbeat from the DOTS server, and MAY consider a
signaling session terminated in the extended absence of a DOTS server heartbeat.


### DOTS Server {#dots-server}

A DOTS server is a DOTS agent capable of receiving, processing and possibly
acting on requests for help coordinating attack response from one or more DOTS
clients.  The DOTS server authenticates and authorizes DOTS clients as described
in Signaling Sessions below, and maintains signaling session state, tracking
requests for mitigation, reporting on the status of active mitigations, and
terminating signaling sessions in the extended absence of a client heartbeat or
when a session times out.

Assuming the preconditions discussed below exist, a DOTS client maintaining an
active signaling session with a DOTS server may reasonably expect some level of
mitigation in response to a request for coordinated attack response.

The DOTS server enforces authorization of DOTS clients' signals for mitigation.
The mechanism of enforcement is not in scope for this document, but is expected
to restrict requested mitigation scope to addresses, prefixes, and/or services
owned by the DOTS client's administrative entity, such that a DOTS client from
one entity is not able to influence the network path to another entity. A DOTS
server MUST reject requests for mitigation of resources not owned by the
requesting DOTS client's administrative entity. A DOTS server MAY also refuse a
DOTS client's mitigation request for arbitrary reasons, within any limits
imposed by business or service level agreements between client and server
domains. If a DOTS server refuses a DOTS client's request for mitigation, the
DOTS server SHOULD include the refusal reason in the server signal sent to the
client.

A DOTS server is in regular contact with one or more mitigators. If a DOTS
server accepts a DOTS client's request for help, the DOTS server forwards a
translated form of that request to the mitigator or mitigators responsible for
scrubbing attack traffic. Note that the form of the translated request passed
from the DOTS server to the mitigator is not in scope: it may be as simple as an
alert to mitigator operators, or highly automated using vendor or open
application programming interfaces supported by the mitigator. The DOTS server
MUST report the actual scope of any mitigation enabled on behalf of a client.

The DOTS server SHOULD retrieve available metrics for any mitigations activated
on behalf of a DOTS client, and SHOULD include them in server signals sent to
the DOTS client originating the request for mitigation.

To provide a metric of signal health and distinguish an idle signaling session
from a disconnected or defunct session, the DOTS server sends a heartbeat over
the signal channel to maintain its half of the signaling session. The DOTS
server similarly expects a heartbeat from the DOTS client, and MAY consider a
signaling session terminated in the extended absence of a DOTS client heartbeat.


### DOTS Gateway {#dots-gateway}

Traditional client to server relationships may be expanded by chaining
DOTS sessions. This chaining is enabled through "logical concatenation"
[RFC7092] of a DOTS server and a DOTS client, resulting in an application
analogous to the SIP logical entity of a Back-to-Back User Agent (B2BUA)
[RFC3261]. The term DOTS gateway will be used here and the following text will
describe some interactions in relation to this application.

A DOTS gateway may be deployed client-side, server-side or both.  The gateway
may terminate multiple discrete client connections and may aggregate these into
a single or multiple DOTS signaling sessions.

The DOTS gateway will appear as a server to its downstream agents and as a
client to its upstream agents, a functional concatenation of the DOTS client and
server roles, as depicted in {{fig-dots-gateway}}:

~~~~~
                      +-------------+
                      |    | D |    |
      +----+          |    | O |    |         +----+
      | c1 |----------| s1 | T | c2 |---------| s2 |
      +----+          |    | S |    |         +----+
                      |    | G |    |
                      +-------------+
~~~~~
{: #fig-dots-gateway title="DOTS gateway"}

The DOTS gateway performs full stack DOTS session termination and reorigination
between its client and server side. The details of how this is achieved are
implementation specific. The DOTS protocol does not include any special features
related to DOTS gateways, and hence from a DOTS perspective, whenever a DOTS
gateway is present, the DOTS session simply terminates/originates there.


DOTS Agent Relationships {#agent-relationships}
------------------------

So far, we have only considered a relatively simple scenario of a single DOTS
client associated with a single DOTS server, however DOTS supports more advanced
relationships.

A DOTS server may be associated with one or more DOTS clients, and those DOTS
clients may belong to different entities. An example scenario is a mitigation
provider serving multiple attack targets ({{fig-multi-client-server}}):

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
{: #fig-multi-client-server title="DOTS server with multiple clients"}

A DOTS client may be associated with one or more DOTS servers, and
those DOTS servers may belong to different entities.  This may be to ensure
high availability or co-ordinate mitigation with more than one directly
connected ISP.  An example scenario is for an enterprise to have DDoS
mitigation service from multiple providers, as shown in
{{fig-multi-homed-client}} below.  Operational considerations relating to
co-ordinating multiple provider responses are beyond the scope of DOTS.

{:ed-note: source="mortensen"}
\[\[EDITOR'S NOTE: we request working group feedback and discussion of
operational considerations relating to coordinating multiple provider responses
to a mitigation request.\]\]
{:mortensen}

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
{: #fig-multi-homed-client title="Multi-Homed DOTS Client"}


### Gatewayed signaling

As discussed above in {{dots-gateway}}, a DOTS gateway is a logical function
chaining signaling sessions through concatenation of a DOTS server and DOTS
client.

An example scenario, as shown in {{fig-client-gateway-agg}} and
{{fig-client-gateway-noagg}} below, is for an enterprise to have deployed
multiple DOTS capable devices which are able to signal intra-domain using TCP
[RFC0793] on un-congested links to a DOTS gateway which may then transform these
to a UDP [RFC0768] transport inter-domain where connection oriented transports
may degrade; this applies to the signal channel only, as the data channel
requires a connection-oriented transport. The relationship between the gateway
and its upstream agents is opaque to the initial clients.

~~~~~
      +---+
      | c |\
      +---+ \              +---+
             \-----TCP-----| D |               +---+
      +---+                | O |               |   |
      | c |--------TCP-----| T |------UDP------| S |
      +---+                | S |               |   |
             /-----TCP-----| G |               +---+
      +---+ /              +---+
      | c |/
      +---+
      example.com       example.com           example.net
      DOTS Clients      DOTS Gateway (DOTSG)  DOTS Server
~~~~~
{: #fig-client-gateway-agg title="Client-Side Gateway with Aggregation"}

~~~~~
      +---+
      | c |\
      +---+ \              +---+
             \-----TCP-----| D |------UDP------+---+
      +---+                | O |               |   |
      | c |--------TCP-----| T |------UDP------| S |
      +---+                | S |               |   |
             /-----TCP-----| G |------UDP------+---+
      +---+ /              +---+
      | c |/
      +---+
      example.com       example.com           example.net
      DOTS Clients      DOTS Gateway (DOTSG)  DOTS Server
~~~~~
{: #fig-client-gateway-noagg title="Client-Side Gateway without Aggregation"}

This may similarly be deployed in the inverse scenario where the gateway resides
in the server-side domain and may be used to terminate and/or aggregate mutiple
clients to single transport as shown in figures {{fig-server-gateway-agg}} and
{{fig-server-gateway-noagg}} below.

~~~~~
      +---+
      | c |\
      +---+ \              +---+
             \-----UDP-----| D |               +---+
      +---+                | O |               |   |
      | c |--------TCP-----| T |------TCP------| S |
      +---+                | S |               |   |
             /-----TCP-----| G |               +---+
      +---+ /              +---+
      | c |/
      +---+
      example.com       example.net           example.net
      DOTS Clients      DOTS Gateway (DOTSG)  DOTS Server
~~~~~
{: #fig-server-gateway-agg title="Server-Side Gateway with Aggregation"}

~~~~~
      +---+
      | c |\
      +---+ \              +---+
             \-----UDP-----| D |------TCP------+---+
      +---+                | O |               |   |
      | c |--------TCP-----| T |------TCP------| S |
      +---+                | S |               |   |
             /-----UDP-----| G |------TCP------+---+
      +---+ /              +---+
      | c |/
      +---+
      example.com       example.net           example.net
      DOTS Clients      DOTS Gateway (DOTSG)  DOTS Server
~~~~~
{: #fig-server-gateway-noagg title="Server-Side Gateway without Aggregation"}


Concepts {#concepts}
========

Signaling Sessions {#signaling-sessions}
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


### Preconditions {#signaling-session-preconditions}

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


### Establishing the Signaling Session {#establishing-signaling-session}

With the required business or service agreements in place, the DOTS client
initiates a signal session by contacting the DOTS server over the signal channel
and the data channel. To allow for DOTS service flexibility, neither the order
of contact nor the time interval between channel creations is specified. A DOTS
client MAY establish signal channel first, and then data channel, or vice versa.

The methods by which a DOTS client receives the address and associated service
details of the DOTS server are not prescribed by this document. For example, a
DOTS client may be directly configured to use a specific DOTS server address and
port, and directly provided with any data necessary to satisfy the Peer Mutual
Authentication requirement in [I-D.ietf-dots-requirements], such as
symmetric or asymmetric keys, usernames and passwords, etc. All configuration
and authentication information in this scenario is provided out-of-band by the
entity operating the DOTS server.

At the other extreme, the architecture in this document allows for a form of
DOTS client auto-provisioning. For example, the entity operating the DOTS server
or servers might provide the client entity only with symmetric or asymmetric
keys to authenticate the provisioned DOTS clients. Only the keys would then be
directly configured on DOTS clients, but the remaining configuration required to
provision the DOTS clients could be learned through mechanisms similar to DNS
SRV {{RFC2782}} or DNS Service Discovery {{RFC6763}}.

The DOTS client SHOULD successfully authenticate and exchange messages with the
DOTS server over both signal and data channel as soon as possible to confirm
that both channels are operational.

Once the DOTS client begins receiving DOTS server signals, the signaling session
is active. At any time during the signaling session, the DOTS client MAY use the
data channel to adjust initial configuration, manage black- and white-listed
prefixes or addresses, leverage vendor-specific extensions, and so on. Note that
unlike the signal channel, there is no requirement that the data channel remain
operational in attack conditions (See Data Channel Requirements,
[I-D.ietf-dots-requirements]).


### Maintaining the Signaling Session {#maintaining-signaling-session}

DOTS clients and servers periodically send heartbeats to each other over the
signal channel, per Operational Requirements discussed in
[I-D.ietf-dots-requirements]. DOTS agent operators SHOULD configure the
heartbeat interval such that the frequency does not lead to accidental denials
of service due to the overwhelming number of heartbeats a DOTS agent must field.

Either DOTS agent may consider a signaling session terminated in the extended
absence of a heartbeat from its peer agent. The period of that absence will be
established in the protocol definition.


Modes of Signaling
------------------

This section examines the modes of signaling between agents in a DOTS
architecture.


### Direct Signaling {#direct-signaling}

A signaling session may take the form of direct signaling between the DOTS
clients and servers, as shown in {{fig-direct-signaling}} below:

~~~~~
        +-------------+                            +-------------+
        | DOTS client |<------signal session------>| DOTS server |
        +-------------+                            +-------------+
~~~~~
{: #fig-direct-signaling title="Direct Signaling"}

In a direct signaling session, DOTS client and server are communicating
directly. A direct signaling session MAY exist inter- or intra-domain. The
signaling session is abstracted from the underlying networks or network elements
the signals traverse: in a direct signaling session, the DOTS client and server
are logically peer DOTS agents.


### Redirected Signaling {#redirected-signaling}

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

A basic redirected signaling session resembles the following, as shown in
{{fig-redirected-signaling}}:

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
{: #fig-redirected-signaling title="Redirected Signaling"}

1. Previously established signaling session 1 exists between a DOTS client and
   DOTS server with address A.

1. DOTS server A sends a server signal redirecting the client to DOTS server B.

1. If the DOTS client does not already have a separate signaling session with
   the redirection target, the DOTS client initiates and establishes a signaling
   session with DOTS server B as described above.

1. Having redirected the DOTS client, DOTS server A ceases sending server
   signals. The DOTS client likewise stops sending client signals to DOTS server
   A. Signal session 1 is terminated.

{:ed-note: source="mortensen"}
\[\[EDITOR'S NOTE: we request working group feedback and discussion of the need
for redirected signaling.\]\]
{:mortensen}

### Recursive Signaling {#recursive-signaling}

DOTS is centered around improving the speed and efficiency of coordinated
response to DDoS attacks. One scenario not yet discussed involves coordination
among federated entities operating DOTS servers and mitigators.

In the course of normal DOTS operations, a DOTS client communicates the need for
mitigation to a DOTS server, and that server initiates mitigation on a
mitigator with which the server has an established service relationship. The
operator of the mitigator may in turn monitor mitigation performance and
capacity, as the attack being mitigated may grow in severity beyond the
mitigating entity's capabilities.

The operator of the mitigator has limited options in the event a DOTS
client-requested mitigation is being overwhelmed by the severity of the attack.
Out-of-scope business or service level agreements may permit the mitigating
entity to drop the mitigation and let attack traffic flow unchecked to the
target, but this is only encourages attack escalation. In the case where
the mitigating entity is the upstream service provider for the attack target,
this may mean the mitigating entity and its other services and users continue to
suffer the incidental effects of the attack.

A recursive signaling model as shown in {{fig-recursive-signaling}} below offers
an alternative. In a variation of the primary use case "Successful Automatic or
Operator-Assisted CPE or PE Mitigators Request Upstream DDoS Mitigation
Services" described in [I-D.ietf-dots-use-cases], an entity operating a DOTS
server and mitigation also operates a DOTS client. This DOTS client has an
established signaling session with a DOTS server belonging to a separate
administrative domain.

With these preconditions in place, the operator of the mitigator being
overwhelmed or otherwise performing inadequately may request mitigation for the
attack target from this separate DOTS-aware entity. Such a request recurses the
originating mitigation request to the secondary DOTS server, in the hope of
building a cumulative mitigation against the attack:

~~~~~
                     example.net entity
                     . . . . . . . . . . . . . . . . .
                     .                               .
       +----+    A   .  +----+       +-----------+   .
       | Cc |<--------->| Sn |~~~~~~~| Mitigator |   .
       +----+        .  +====+       |     Mn    |   .
                     .  | Cn |       +-----------+   .
     example.com     .  +----+                       .
        client       .    ^                          .
                     . . .|. . . . . . . . . . . . . .
                          |
                        B |
                          |
                     . . .|. . . . . . . . . . . . . .
                     .    v                          .
                     .  +----+       +-----------+   .
                     .  | So |~~~~~~~| Mitigator |   .
                     .  +----+       |     Mo    |   .
                     .               +-----------+   .
                     .                               .
                     . . . . . . . . . . . . . . . . .
                     example.org entity
~~~~~
{: #fig-recursive-signaling title="Recursive Signaling"}

In {{fig-recursive-signaling}} above, client Cc signals a request for mitigation
across inter-domain signaling session A to the DOTS server Sn belonging to the
example.net entity. DOTS server Sn enables mitigation on mitigator Mn. DOTS
server Sn is logically back-to-back with DOTS client Cn, which has pre-existing
inter-domain signaling session B with the DOTS server So belonging to the
example.org entity. At any point, DOTS server Sn MAY recurse an on-going
mitigation request through DOTS client Cn to DOTS server So, in the expectation
that mitigator Mo will be activated to aid in the defense of the attack target.

Recursive signaling is opaque to the DOTS client. To maximize mitigation
visibility to the DOTS client, however, the recursing entity SHOULD provide
recursed mitigation feedback in signals reporting on mitigation status to the
DOTS client. For example, the recursing entity's mitigator should incorporate
into mitigation status messages available metrics such as dropped packet or byte
counts from the recursed mitigation.

DOTS clients involved in recursive signaling MUST be able to withdraw requests
for mitigation without warning or justification, per
[I-D.ietf-dots-requirements].

Operators recursing mitigation requests MAY maintain the recursed mitigation for
a brief, protocol-defined period in the event the DOTS client originating the
mitigation withdraws its request for help, as per the discussion of managing
mitigation toggling in the operational requirements
([I-D.ietf-dots-requirements]).  Service or business agreements between
recursing entities are not in scope for this document.

{:ed-note: source="mortensen"}
\[\[EDITOR'S NOTE: Recursive signaling raises questions about operational and
data privacy, as well as what level of visibility a client has into the recursed
mitigation.  We ask the working group for feedback and additional discussion of
these issues to help settle the way forward.\]\]
{:mortensen}


Security Considerations         {#security-considerations}
=======================

This section describes identified security considerations for the DOTS
architecture.

DOTS is at risk from three primary attack vectors:  agent impersonation,
traffic injection and signal blocking.  These vectors may be exploited
individually or in concert by an attacker to confuse, disable, take information
from, or otherwise inhibit the DOTS system.

Any attacker with the ability to impersonate a legitimate client or server or,
indeed, inject false messages into the stream may potentially trigger/withdraw
traffic redirection, trigger/cancel mitigation activities or subvert
black/whitelists.  From an architectural standpoint, operators SHOULD ensure
best current practices for secure communication are observed for data and
signal channel confidentiality, integrity and authenticity.  Care must be taken
to ensure transmission is protected by appropriately secure means, reducing
attack surface by exposing only the minimal required services or interfaces.
Similarly, received data at rest SHOULD be stored with a satisfactory degree of
security.

As many mitigation systems employ diversion to scrub attack traffic, operators
of DOTS agents SHOULD ensure signaling sessions are resistant to
Man-in-the-Middle (MitM) attacks. An attacker with control of a DOTS client may
negatively influence network traffic by requesting and withdrawing requests for
mitigation for particular prefixes, leading to route or DNS flapping.

Any attack targeting the availability of DOTS servers may disrupt the ability
of the system to receive and process DOTS signals resulting in failure to
fulfill a mitigation request.  DOTS systems SHOULD be given adequate
protections, again in accordance with best current practices for network and
host security.


Acknowledgments                 {#acknowledgments}
===============

Thanks to Matt Richardson and Med Boucadair for their comments and suggestions.


Change Log
==========

2016-03-18      Initial revision
