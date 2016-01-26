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

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.


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

TBD

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

