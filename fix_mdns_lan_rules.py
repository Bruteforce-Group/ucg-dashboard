#!/usr/bin/env python3
"""
Fix mDNS and Multicast Rules for LAN (192.168.22.x)
Creates rules to ALLOW mDNS and multicast traffic on managed networks
"""

import requests
import json
import time
from datetime import datetime

class UCGmDNSFixer:
    def __init__(self, controller_url="https://192.168.22.1:8443", api_key="C5tSpDSC2J_bZy9oqYwBDesWoUP1sHIK"):
        self.controller_url = controller_url
        self.api_key = api_key
        self.api_base = f"{controller_url}/proxy/network/api/s/default"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'X-API-KEY': self.api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
    def create_lan_mdns_rules(self):
        """Create rules to ALLOW mDNS and multicast on LAN"""
        
        # Get current rules to find next rule_index
        try:
            response = self.session.get(f"{self.api_base}/rest/firewallrule")
            if response.status_code == 200:
                existing_rules = response.json().get('data', [])
                max_rule_index = max([rule.get('rule_index', 0) for rule in existing_rules if rule.get('rule_index')], default=20000)
                next_rule_index = max_rule_index + 1
            else:
                next_rule_index = 20000
        except:
            next_rule_index = 20000
            
        print(f"Creating LAN mDNS rules starting at rule_index: {next_rule_index}")
        
        # Rule 1: Allow mDNS (port 5353) on LAN_IN
        mdns_lan_in_rule = {
            "name": "Allow_mDNS_LAN_IN",
            "enabled": True,
            "action": "accept",
            "ruleset": "LAN_IN",
            "rule_index": next_rule_index,
            "protocol": "udp",
            "src_address": "192.168.22.0/24",
            "dst_address": "224.0.0.251",
            "dst_port": "5353",
            "logging": False
        }
        
        # Rule 2: Allow mDNS (port 5353) on LAN_OUT  
        mdns_lan_out_rule = {
            "name": "Allow_mDNS_LAN_OUT",
            "enabled": True,
            "action": "accept",
            "ruleset": "LAN_OUT",
            "rule_index": next_rule_index + 1,
            "protocol": "udp",
            "src_address": "192.168.22.0/24",
            "dst_address": "224.0.0.251",
            "dst_port": "5353",
            "logging": False
        }
        
        # Rule 3: Allow LLMNR (port 5355) on LAN_IN
        llmnr_lan_in_rule = {
            "name": "Allow_LLMNR_LAN_IN",
            "enabled": True,
            "action": "accept",
            "ruleset": "LAN_IN",
            "rule_index": next_rule_index + 2,
            "protocol": "udp",
            "src_address": "192.168.22.0/24",
            "dst_address": "224.0.0.252",
            "dst_port": "5355",
            "logging": False
        }
        
        # Rule 4: Allow LLMNR (port 5355) on LAN_OUT
        llmnr_lan_out_rule = {
            "name": "Allow_LLMNR_LAN_OUT",
            "enabled": True,
            "action": "accept",
            "ruleset": "LAN_OUT",
            "rule_index": next_rule_index + 3,
            "protocol": "udp",
            "src_address": "192.168.22.0/24",
            "dst_address": "224.0.0.252",
            "dst_port": "5355",
            "logging": False
        }
        
        # Rule 5: Allow general multicast on LAN_IN
        multicast_lan_in_rule = {
            "name": "Allow_Multicast_LAN_IN",
            "enabled": True,
            "action": "accept",
            "ruleset": "LAN_IN",
            "rule_index": next_rule_index + 4,
            "protocol": "udp",
            "src_address": "192.168.22.0/24",
            "dst_address": "224.0.0.0/4",
            "logging": False
        }
        
        # Rule 6: Allow general multicast on LAN_OUT
        multicast_lan_out_rule = {
            "name": "Allow_Multicast_LAN_OUT",
            "enabled": True,
            "action": "accept",
            "ruleset": "LAN_OUT",
            "rule_index": next_rule_index + 5,
            "protocol": "udp",
            "src_address": "192.168.22.0/24",
            "dst_address": "224.0.0.0/4",
            "logging": False
        }
        
        rules = [
            mdns_lan_in_rule, mdns_lan_out_rule,
            llmnr_lan_in_rule, llmnr_lan_out_rule,
            multicast_lan_in_rule, multicast_lan_out_rule
        ]
        
        created_rules = []
        failed_rules = []
        
        for rule in rules:
            try:
                print(f"Creating rule: {rule['name']}")
                response = self.session.post(f"{self.api_base}/rest/firewallrule", json=rule)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('meta', {}).get('rc') == 'ok':
                        created_rules.append(rule['name'])
                        print(f"✅ Created: {rule['name']}")
                    else:
                        failed_rules.append(f"{rule['name']}: {result}")
                        print(f"❌ Failed: {rule['name']} - {result}")
                else:
                    failed_rules.append(f"{rule['name']}: HTTP {response.status_code}")
                    print(f"❌ Failed: {rule['name']} - HTTP {response.status_code}")
                    
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                failed_rules.append(f"{rule['name']}: {str(e)}")
                print(f"❌ Error creating {rule['name']}: {str(e)}")
        
        return created_rules, failed_rules

def main():
    print("🔧 UCG mDNS LAN Rules Fixer")
    print("=" * 50)
    
    fixer = UCGmDNSFixer()
    
    print("Creating LAN mDNS and multicast ALLOW rules...")
    created, failed = fixer.create_lan_mdns_rules()
    
    print("\n📊 RESULTS:")
    print(f"✅ Created: {len(created)} rules")
    for rule in created:
        print(f"   - {rule}")
    
    if failed:
        print(f"❌ Failed: {len(failed)} rules")
        for rule in failed:
            print(f"   - {rule}")
    
    print("\n🎯 These rules will allow:")
    print("   - mDNS (port 5353) on 192.168.22.x")
    print("   - LLMNR (port 5355) on 192.168.22.x") 
    print("   - General multicast (224.0.0.0/4) on 192.168.22.x")
    print("   - Both LAN_IN and LAN_OUT directions")

if __name__ == "__main__":
    main()
