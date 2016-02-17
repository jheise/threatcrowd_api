#!/usr/bin/env python
from threatcrowd import *
import time

print email_report("name@email.com")
print ip_report("4.2.2.1")
print domain_report("google.com")
print antivirus_report("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

tc = ThreatCrowd(ttl=5)
print tc.ip_report("4.2.2.1")
print tc.ip_report("4.2.2.1")

print "sleeping longer than the ttl"
time.sleep(6)
print tc.ip_report("4.2.2.1")
