#!/usr/bin/env python3
"""
Quick check for firewall rules in UniFi API
"""

import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_firewall_rules():
    """Check for firewall rules in the API"""
    api_key = "C5tSpDSC2J_bZy9oqYwBDesWoUP1sHIK"
    url = "https://192.168.22.1/proxy/network/api/s/default/rest/firewallrule"
    
    headers = {
        'X-API-KEY': api_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            rules = data.get('data', [])
            print(f"\nFound {len(rules)} firewall rules:")
            
            for i, rule in enumerate(rules):
                print(f"\nRule {i+1}:")
                print(json.dumps(rule, indent=2))
                
        return response.status_code == 200
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("Checking for firewall rules...")
    check_firewall_rules()
