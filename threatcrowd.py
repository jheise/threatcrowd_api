import requests
import json
import time

def _threatcrowd_query(path, params):
    full_path = "http://www.threatcrowd.org/searchApi/v2/{0}/report/".format(path)
    data = requests.get(full_path, params=params).text
    return json.loads(data)

def email_report(address):
    return _threatcrowd_query("email", {"email":address})

def ip_report(address):
    return _threatcrowd_query("ip", {"ip":address})

def domain_report(domain):
    return _threatcrowd_query("domain", {"domain":domain})

def antivirus_report(antivirus):
    return _threatcrowd_query("antivirus", {"antivirus":antivirus})

class ThreatCrowd(object):
    """
    Class to handle memozing calls
    """

    def __init__(self, ttl=14400):
        super(ThreatCrowd, self).__init__()
        self.ttl = ttl
        self.calls = {
            "email":{},
            "ip":{},
            "domain":{},
            "antivirus":{}
        }

    def email_report(self, address):
        return self.__process_call("email", address)

    def ip_report(self, address):
        return self.__process_call("ip", address)

    def domain_report(self, domain):
        return self.__process_call("domain", domain)

    def antivirus_report(self, antivirus):
        return self.__process_call("antivirus", antivirus)

    def __process_call(self, path, param):
        current_time = time.time()

        if param in self.calls[path]:
            diff = current_time - self.calls[path][param]["time"]
            if diff < self.ttl:
                print "returning value form memory"
                return self.calls[path][param]["result"]

        # either there isnt a result or the ttl has expired, query from source
        print "query for new result"
        result = _threatcrowd_query(path, {path:param})
        if param not in self.calls[path]:
            self.calls[path][param] = {}

        self.calls[path][param]["result"] = result
        self.calls[path][param]["time"] = current_time

        return result
