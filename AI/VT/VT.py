import requests
import json
from tld import get_tld
from time import sleep

VT_API_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

def VT_scan_url(domain):
    
    url = "https://www.virustotal.com/api/v3/urls"
    
    payload = {"url":domain}
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    
    res = requests.post(url,data = payload,headers=headers)
    return json.loads(res.text)

def VT_analysis_url(url):
    
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    res = requests.get(url,headers=headers)

    return json.loads(res.text)
    
def vt_test(domain):
    res = 0
    
    scan_result = VT_scan_url(domain)
    links = scan_result.get("data").get("links").get("self")
    sleep(1.5)
    analysis_result = VT_analysis_url(links)
    
    malicious_rate = analysis_result.get("data").get("attributes").get("stats").get("malicious")
    # print("rate: ",malicious_rate)
    if malicious_rate >2:
        res = 1
    
    return res