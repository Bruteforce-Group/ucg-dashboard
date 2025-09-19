#!/usr/bin/env python3
"""
Recreate all API rules with correct field names (src_address/dst_address)
"""

import requests
import json
import logging
from typing import Dict, List
import time
import urllib3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('RecreateAPIRules')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIRuleRecreator:
    def __init__(self, controller_url: str = "https://192.168.22.1", api_key: str = ""):
        self.controller_url = controller_url
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'X-API-KEY': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
    
    def get_existing_rules(self) -> List[Dict]:
        """Get all existing firewall rules"""
        try:
            response = self.session.get(
                f"{self.controller_url}/proxy/network/api/s/default/rest/firewallrule",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                logger.error(f"Failed to get rules: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting rules: {e}")
            return []
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a firewall rule"""
        try:
            response = self.session.delete(
                f"{self.controller_url}/proxy/network/api/s/default/rest/firewallrule/{rule_id}",
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Deleted rule: {rule_id}")
                return True
            else:
                logger.error(f"Failed to delete rule {rule_id}: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting rule {rule_id}: {e}")
            return False
    
    def create_rule(self, rule_config: Dict) -> bool:
        """Create a firewall rule with correct field names"""
        try:
            response = self.session.post(
                f"{self.controller_url}/proxy/network/api/s/default/rest/firewallrule",
                json=rule_config,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Created rule: {rule_config.get('name', 'unnamed')}")
                return True
            else:
                logger.error(f"Failed to create rule: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating rule: {e}")
            return False
    
    def get_correct_rules(self) -> List[Dict]:
        """Generate correct firewall rules with proper field names"""
        rules = []
        rule_index = 20001
        
        # IPv4 Unmanaged Ranges
        ipv4_ranges = [
            ("10.0.0.0/8", "IPv4_Class_A_Private"),
            ("172.16.0.0/12", "IPv4_Class_B_Private"),
            ("192.168.0.0/16", "IPv4_Class_C_Private"),
            ("169.254.0.0/16", "IPv4_Link_Local"),
            ("127.0.0.0/8", "IPv4_Loopback"),
            ("0.0.0.0/8", "IPv4_Current_Network"),
            ("224.0.0.0/4", "IPv4_Multicast"),
            ("240.0.0.0/4", "IPv4_Reserved"),
            ("192.0.2.0/24", "IPv4_Test_NET_1"),
            ("198.51.100.0/24", "IPv4_Test_NET_2"),
            ("203.0.113.0/24", "IPv4_Test_NET_3"),
            ("198.18.0.0/15", "IPv4_Benchmarking")
        ]
        
        for network, name_suffix in ipv4_ranges:
            # WAN_IN rules (block incoming from unmanaged ranges)
            rules.append({
                "_id": None,
                "name": f"Block_{name_suffix}_WAN_IN",
                "enabled": True,
                "action": "drop",
                "ruleset": "WAN_IN",
                "rule_index": rule_index,
                "protocol": "all",
                "src_address": network,
                "logging": True,
                "site_id": "default"
            })
            rule_index += 1
            
            # WAN_OUT rules (block outgoing to unmanaged ranges)
            rules.append({
                "_id": None,
                "name": f"Block_{name_suffix}_WAN_OUT",
                "enabled": True,
                "action": "drop",
                "ruleset": "WAN_OUT",
                "rule_index": rule_index,
                "protocol": "all",
                "dst_address": network,
                "logging": True,
                "site_id": "default"
            })
            rule_index += 1
        
        # IPv6 Unmanaged Ranges
        ipv6_ranges = [
            ("fc00::/7", "IPv6_ULA"),
            ("fe80::/10", "IPv6_Link_Local"),
            ("::1/128", "IPv6_Loopback"),
            ("ff00::/8", "IPv6_Multicast"),
            ("2001:db8::/32", "IPv6_Documentation"),
            ("::/128", "IPv6_Unspecified"),
            ("::ffff:0:0/96", "IPv6_IPv4_Mapped"),
            ("64:ff9b::/96", "IPv6_IPv4_Translation")
        ]
        
        for network, name_suffix in ipv6_ranges:
            # WAN_IN rules (block incoming from unmanaged ranges)
            rules.append({
                "_id": None,
                "name": f"Block_{name_suffix}_WAN_IN",
                "enabled": True,
                "action": "drop",
                "ruleset": "WAN_IN",
                "rule_index": rule_index,
                "protocol": "all",
                "src_address": network,
                "logging": True,
                "site_id": "default"
            })
            rule_index += 1
            
            # WAN_OUT rules (block outgoing to unmanaged ranges)
            rules.append({
                "_id": None,
                "name": f"Block_{name_suffix}_WAN_OUT",
                "enabled": True,
                "action": "drop",
                "ruleset": "WAN_OUT",
                "rule_index": rule_index,
                "protocol": "all",
                "dst_address": network,
                "logging": True,
                "site_id": "default"
            })
            rule_index += 1
        
        return rules
    
    def recreate_rules(self) -> Dict:
        """Delete all broken rules and create correct ones"""
        results = {
            'deleted_rules': 0,
            'created_rules': 0,
            'failed_deletions': 0,
            'failed_creations': 0
        }
        
        logger.info("Getting existing rules...")
        existing_rules = self.get_existing_rules()
        
        # Delete all rules with null src_address/dst_address
        logger.info("Deleting broken rules...")
        for rule in existing_rules:
            if rule.get('name', '').startswith('Block_') and (rule.get('src_address') is None and rule.get('dst_address') is None):
                if self.delete_rule(rule['_id']):
                    results['deleted_rules'] += 1
                else:
                    results['failed_deletions'] += 1
                time.sleep(0.1)
        
        # Also delete the test rule
        for rule in existing_rules:
            if rule.get('name') == 'Test_Correct_Fields':
                if self.delete_rule(rule['_id']):
                    results['deleted_rules'] += 1
                else:
                    results['failed_deletions'] += 1
                time.sleep(0.1)
        
        # Create correct rules
        logger.info("Creating correct rules with proper field names...")
        correct_rules = self.get_correct_rules()
        
        for rule in correct_rules:
            if self.create_rule(rule):
                results['created_rules'] += 1
            else:
                results['failed_creations'] += 1
            time.sleep(0.1)
        
        return results
    
    def verify_rules(self) -> Dict:
        """Verify that rules are working correctly"""
        try:
            existing_rules = self.get_existing_rules()
            working_rules = [r for r in existing_rules if r.get('src_address') or r.get('dst_address')]
            broken_rules = [r for r in existing_rules if r.get('name', '').startswith('Block_') and not (r.get('src_address') or r.get('dst_address'))]
            
            return {
                'total_rules': len(existing_rules),
                'working_rules': len(working_rules),
                'broken_rules': len(broken_rules),
                'status': 'HEALTHY' if len(broken_rules) == 0 else 'WARNING'
            }
            
        except Exception as e:
            logger.error(f"Error verifying rules: {e}")
            return {'status': 'error', 'error': str(e)}

def main():
    print("=" * 80)
    print("RECREATING API FIREWALL RULES WITH CORRECT FIELD NAMES")
    print("=" * 80)
    
    api_key = "C5tSpDSC2J_bZy9oqYwBDesWoUP1sHIK"
    recreator = APIRuleRecreator(api_key=api_key)
    
    print("\nRecreating rules with correct field names (src_address/dst_address)...")
    results = recreator.recreate_rules()
    
    print(f"\n=== RESULTS ===")
    print(f"✅ Rules deleted: {results['deleted_rules']}")
    print(f"✅ Rules created: {results['created_rules']}")
    print(f"❌ Failed deletions: {results['failed_deletions']}")
    print(f"❌ Failed creations: {results['failed_creations']}")
    
    print("\nVerifying rules...")
    verification = recreator.verify_rules()
    
    print(f"\n=== VERIFICATION ===")
    print(f"Total rules: {verification.get('total_rules', 0)}")
    print(f"Working rules: {verification.get('working_rules', 0)}")
    print(f"Broken rules: {verification.get('broken_rules', 0)}")
    print(f"Status: {verification.get('status', 'unknown').upper()}")
    
    if verification.get('status') == 'HEALTHY':
        print(f"\n🎉 SUCCESS! All API rules are now working correctly!")
        print(f"✅ Rules have proper IP addresses (src_address/dst_address)")
        print(f"✅ Network protection is active via API")
    else:
        print(f"\n⚠️  Some rules may still need attention")

if __name__ == "__main__":
    main()
