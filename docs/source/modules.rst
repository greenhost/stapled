==================
Module description
==================

Ocspd consists of several modules that interact with each other in order to keep
OCSP staples up-to-date. In short, these are the modules:

:Scheduler:
    It is possible to schedule a task with the scheduler. It will wait
    for the scheduled moment and add the task to a queue to be handled by one
    of the other modules.
:Finder:
    Finds certificates in the specified directories. When new file are found,
    or existing files are changed it schedules a parsing for these
    certificates.
:Parser:
    Parses certificates and parses them. If certificates are correct, it
    schedules a renewal for these certificates.
:Renewer:
    The renewer takes input from the scheduler. It contacts the CA to
    renew an OCSP staple. After renewing the staple it schedules a new
    renewal and tells the scheduler to call the adder right away.
:Adder:
    This is a module that can talk to the HAProxy socket to add OCSP
    staples without restarting HAProxy.

This graph explains their interaction. Every arrow passes a
:class:`~core.certmodel.CertModel` instance to the other module.

.. graphviz::

   digraph {
       graph [fontsize=10, margin=.001, fontname="helvetica" pad=".001", ranksep="1", nodesep="0.001"];
       node [fontname="helvetica"];
       edge [fontname="helvetica"];
       scheduler [label="\nSchedulerThread\n\n🕐" URL="core.html#core.scheduling.SchedulerThread"]
       finder [label="CertFinderThread" URL="core.html#core.certfinder.CertFinderThread"]
       parser [label="CertParserThread" URL="core.html#core.certparser.CertParserThread"]
       renewer [label="OCSPRenewerThread" URL="core.html#core.ocsprenewer.OCSPRenewerThread"]
       adder [label="OCSPAdder" URL="core.html#core.ocspadder.OCSPAdder"]
       haproxy [label=HAProxy shape=box URL="https://www.haproxy.com/"]
       ca[label="Certificate Authority" shape=box URL="https://en.wikipedia.org/wiki/Certificate_authority"]
       finder -> scheduler [label="  schedule next renewal"];
       parser -> scheduler [label=" schedule parsing  "]
       scheduler -> parser [dir="both" label="  parse cert "]
       scheduler -> renewer [dir="both" label="  renew staple    "]
       renewer -> ca [label="  renew staple"]
       renewer -> scheduler [label=" schedule renewal  "]
       scheduler -> adder [dir="both" label="  add staple  "]
       adder -> haproxy [label="  add staple  "]
   }
