#ThreatCrowd API
---

Python Library for ThreatCrowd's API


Functions

- email_report(address) - query for the given email address

- ip_report(address) - query for the given ip address

- domain_report(domain) - query for the given domain

- antivirus_report(av) - query for the given antivirus entry


Classes

- ThreadCrowd(ttl) - Object that can perform the previous queries, but caches answers
for the specificed ttl in seconds.

---
Example

```python
import threatcrowd

print threatcrowd.ip_report("4.2.2.1")

tc = threatcrowd.ThreatCrowd(ttl=5) # make an object with a ttl of 5 seconds
print tc.ip_report("4.2.2.1")

# print the exact same answer because we are under the ttl
print tc.ip_report("4.2.2.1")

# expire the ttl
import time
time.sleep(6)

# this will fetch and cache a new copy
print tc.ip_report("4.2.2.1")
```
