#!/usr/bin/env python
from ..threatcrowd import *
import time

print email_report("william19770319@yahoo.com")
print ip_report("4.2.2.1")
print domain_report("google.com")
print antivirus_report("Heur.Trojan.Hlux")
print file_report("000c104c074b6a8d24ac362220f16080")

tc = ThreatCrowd(ttl=5)
print tc.ip_report("4.2.2.1")
print tc.ip_report("4.2.2.1")

print "sleeping longer than the ttl"
time.sleep(6)
print tc.ip_report("4.2.2.1")
