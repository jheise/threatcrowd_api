import requests
import json

def __threatcrowd_query(path, params):
    full_path = "http://www.threatcrowd.org/searchApi/v2/{0}/report/".format(path)
    data = requests.get(full_path, params=params).text
    return json.loads(data)

def email_report(address):
    return __threatcrowd_query("email", {"email":address})

def ip_report(address):
    return __threatcrowd_query("ip", {"ip":address})

def domain_report(domain):
    return __threatcrowd_query("domain", {"domain":domain})

def antivirus_report(antivirus):
    return __threatcrowd_query("antivirus", {"antivirus":antivirus})
