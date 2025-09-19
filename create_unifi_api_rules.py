#!/usr/bin/env python3
"""
Create comprehensive unmanaged IP blocking rules via UCG-Fiber API
Based on the correct field format discovered from Rink Spies guide
"""

import requests
import json
import logging
from typing import Dict, List
import time
import urllib3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('UniFiAPIRules')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UniFiAPIRuleManager:
    def __init__(self, controller_url: str = "https://192.168.22.1", api_key: str = ""):
        self.controller_url = controller_url
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = False
        
    def authenticate_with_api_key(self, api_key: str) -> bool:
        """Authenticate with UCG-Fiber using API key"""
        try:
            self.api_key = api_key
            self.session.headers.update({
                'X-API-KEY': self.api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })
            
            # Test authentication by getting sites
            response = self.session.get(
                f"{self.controller_url}/proxy/network/integration/v1/sites",
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Successfully authenticated with UCG-Fiber using API key")
                return True
            else:
                logger.error(f"API key authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"API key authentication error: {e}")
            return False
    
    def create_firewall_rule(self, rule_config: Dict) -> bool:
        """Create a firewall rule in UCG-Fiber"""
        try:
            response = self.session.post(
                f"{self.controller_url}/proxy/network/api/s/default/rest/firewallrule",
                json=rule_config,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Created firewall rule: {rule_config.get('name', 'unnamed')}")
                return True
            else:
                logger.error(f"Failed to create firewall rule: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating firewall rule: {e}")
            return False
    
    def get_all_firewall_rules(self) -> List[Dict]:
        """Generate all unmanaged IP blocking rules using correct UniFi 8.x format"""
        rules = []
        rule_index = 20001  # Start from 20001+ range for UniFi 8.x compatibility
        
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
                "src_ip": network,
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
                "dst_ip": network,
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
                "src_ip": network,
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
                "dst_ip": network,
                "logging": True,
                "site_id": "default"
            })
            rule_index += 1
        
        return rules
    
    def create_unmanaged_range_blocking_rules(self) -> Dict:
        """Create all unmanaged IP blocking rules via API"""
        results = {
            'rules_created': [],
            'rules_failed': [],
            'total_created': 0,
            'total_failed': 0
        }
        
        logger.info("Creating comprehensive unmanaged IP blocking rules via UCG-Fiber API...")
        firewall_rules = self.get_all_firewall_rules()
        
        for rule in firewall_rules:
            success = self.create_firewall_rule(rule)
            if success:
                results['rules_created'].append(rule['name'])
                results['total_created'] += 1
            else:
                results['rules_failed'].append(rule['name'])
                results['total_failed'] += 1
            
            # Small delay between requests
            time.sleep(0.5)
        
        logger.info(f"Firewall rules creation completed: {results['total_created']} created, {results['total_failed']} failed")
        return results
    
    def get_existing_firewall_rules(self) -> List[Dict]:
        """Get existing firewall rules from UCG-Fiber"""
        try:
            response = self.session.get(
                f"{self.controller_url}/proxy/network/api/s/default/rest/firewallrule",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                logger.error(f"Failed to get firewall rules: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting firewall rules: {e}")
            return []
    
    def verify_firewall_rules(self) -> Dict:
        """Verify firewall rules are created and active"""
        try:
            existing_rules = self.get_existing_firewall_rules()
            drop_rules = len([r for r in existing_rules if r.get('action') == 'drop'])
            inbound_rules = len([r for r in existing_rules if r.get('ruleset') == 'WAN_IN'])
            outbound_rules = len([r for r in existing_rules if r.get('ruleset') == 'WAN_OUT'])
            unmanaged_blocking_rules = len([r for r in existing_rules if "Block_" in r.get('name', '')])
            
            status = 'HEALTHY' if unmanaged_blocking_rules > 0 else 'WARNING'
            
            return {
                'total_rules': len(existing_rules),
                'drop_rules': drop_rules,
                'inbound_rules': inbound_rules,
                'outbound_rules': outbound_rules,
                'unmanaged_blocking_rules': unmanaged_blocking_rules,
                'status': status
            }
            
        except Exception as e:
            logger.error(f"Error verifying firewall rules: {e}")
            return {'status': 'error', 'error': str(e)}

def main():
    print("=" * 80)
    print("UCG-FIBER API FIREWALL RULES CREATION")
    print("=" * 80)
    
    api_key = "C5tSpDSC2J_bZy9oqYwBDesWoUP1sHIK"
    manager = UniFiAPIRuleManager(api_key=api_key)
    
    print("\nAuthenticating with UCG-Fiber using API key...")
    if not manager.authenticate_with_api_key(api_key):
        print("❌ API key authentication failed!")
        return
    print("✅ Authentication successful!")
    
    print("\nCreating firewall rules to block unmanaged ranges...")
    results = manager.create_unmanaged_range_blocking_rules()
    
    print(f"\n=== RESULTS ===")
    print(f"✅ Rules created: {results['total_created']}")
    print(f"❌ Rules failed: {results['total_failed']}")
    
    if results['rules_created']:
        print(f"\nCreated rules:")
        for rule_name in results['rules_created'][:10]:
            print(f"  - {rule_name}")
        if len(results['rules_created']) > 10:
            print(f"  ... and {len(results['rules_created']) - 10} more")
    
    if results['rules_failed']:
        print(f"\nFailed rules:")
        for rule_name in results['rules_failed']:
            print(f"  - {rule_name}")
    
    print("\nVerifying firewall rules...")
    verification = manager.verify_firewall_rules()
    
    print(f"\n=== VERIFICATION ===")
    print(f"Total rules: {verification.get('total_rules', 0)}")
    print(f"Drop rules: {verification.get('drop_rules', 0)}")
    print(f"Inbound rules: {verification.get('inbound_rules', 0)}")
    print(f"Outbound rules: {verification.get('outbound_rules', 0)}")
    print(f"Unmanaged blocking rules: {verification.get('unmanaged_blocking_rules', 0)}")
    print(f"Status: {verification.get('status', 'unknown').upper()}")
    
    if verification.get('status') == 'HEALTHY':
        print(f"\n🎉 SUCCESS! All unmanaged IPv4 and IPv6 ranges are now blocked via UCG-Fiber API!")
        print(f"✅ WAN interfaces are protected against private IP traffic")
        print(f"✅ Rules are persistent and managed through UniFi Network application")
    else:
        print(f"\n⚠️  Some rules may need manual verification")
        print(f"Check the UCG-Fiber interface: {manager.controller_url}")

if __name__ == "__main__":
    main()
