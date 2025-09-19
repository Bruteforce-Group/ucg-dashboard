#!/usr/bin/env python3
"""
Create UniFi API firewall rules to allow all traffic on specific subnets
"""

import requests
import json
import sys
from typing import Dict, List

class UniFiSubnetAllowRules:
    def __init__(self, controller_url: str = "https://192.168.22.1", api_key: str = "C5tSpDSC2J_bZy9oqYwBDesWoUP1sHIK"):
        self.controller_url = controller_url
        self.api_key = api_key
        self.api_base = f"{self.controller_url}/proxy/network/api/s/default"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'X-API-KEY': api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
    def authenticate(self) -> bool:
        """Test API authentication"""
        try:
            response = self.session.get(f"{self.controller_url}/proxy/network/integration/v1/sites", timeout=10)
            if response.status_code == 200:
                print("✅ API authentication successful")
                return True
            else:
                print(f"❌ API authentication failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ API authentication error: {e}")
            return False
    
    def create_subnet_allow_rules(self) -> bool:
        """Create firewall rules to allow all traffic on specified subnets"""
        
        # Get current rule index
        try:
            response = self.session.get(f"{self.api_base}/rest/firewallrule", timeout=10)
            if response.status_code == 200:
                existing_rules = response.json().get('data', [])
                max_rule_index = max([rule.get('rule_index', 0) for rule in existing_rules], default=20000)
                rule_index = max_rule_index + 1
            else:
                rule_index = 20000
        except:
            rule_index = 20000
        
        print(f"📋 Starting rule creation with rule_index: {rule_index}")
        
        # Get the site ID from existing rules
        site_id = "68166867e027cb4dd9ef94c6"  # From the existing rules
        
        # Define subnet allow rules
        subnet_rules = [
            {
                "setting_preference": "manual",
                "name": "ALLOW: 172.16.6.0/24 IPv4 Subnet",
                "enabled": True,
                "action": "accept",
                "rule_index": rule_index,
                "src_address": "172.16.6.0/24",
                "protocol": "all",
                "ruleset": "LAN_IN",
                "logging": False,
                "site_id": site_id,
                "_id": None
            },
            {
                "setting_preference": "manual",
                "name": "ALLOW: IPv6 Traffic LAN_IN",
                "enabled": True,
                "action": "accept",
                "rule_index": rule_index + 1,
                "protocol": "all",
                "ruleset": "LAN_IN",
                "logging": False,
                "site_id": site_id,
                "_id": None
            }
        ]
        
        success_count = 0
        
        for rule in subnet_rules:
            try:
                print(f"🔧 Creating rule: {rule['name']}")
                response = self.session.post(f"{self.api_base}/rest/firewallrule", json=rule, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('meta', {}).get('rc') == 'ok':
                        print(f"✅ Successfully created: {rule['name']}")
                        success_count += 1
                    else:
                        print(f"❌ Failed to create {rule['name']}: {result}")
                else:
                    print(f"❌ Failed to create {rule['name']}: {response.status_code} - {response.text}")
                    
            except Exception as e:
                print(f"❌ Error creating {rule['name']}: {e}")
        
        print(f"\n📊 Results: {success_count}/{len(subnet_rules)} rules created successfully")
        return success_count == len(subnet_rules)
    
    def verify_rules(self) -> bool:
        """Verify the created rules exist"""
        try:
            response = self.session.get(f"{self.api_base}/rest/firewallrule", timeout=10)
            if response.status_code == 200:
                rules = response.json().get('data', [])
                
                # Check for our subnet allow rules
                subnet_rules = [rule for rule in rules if '172.16.6.0/24' in rule.get('src_address', '') or 'fdd0:0:0:6::/64' in rule.get('src_address', '')]
                
                print(f"\n🔍 Found {len(subnet_rules)} subnet allow rules:")
                for rule in subnet_rules:
                    print(f"  - {rule.get('name', 'Unknown')} (enabled: {rule.get('enabled', False)})")
                
                return len(subnet_rules) >= 2
            else:
                print(f"❌ Failed to verify rules: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error verifying rules: {e}")
            return False

def main():
    print("🚀 Creating UniFi API subnet allow rules...")
    
    # Initialize the rule manager
    rule_manager = UniFiSubnetAllowRules()
    
    # Authenticate
    if not rule_manager.authenticate():
        print("❌ Authentication failed. Exiting.")
        sys.exit(1)
    
    # Create the rules
    if rule_manager.create_subnet_allow_rules():
        print("✅ All subnet allow rules created successfully!")
        
        # Verify the rules
        if rule_manager.verify_rules():
            print("✅ Rules verified successfully!")
        else:
            print("⚠️  Rules created but verification failed")
    else:
        print("❌ Failed to create some subnet allow rules")
        sys.exit(1)

if __name__ == "__main__":
    main()
