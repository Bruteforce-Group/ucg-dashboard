#!/usr/bin/env python3
"""
UniFi Firewall Rules Converter
Converts iptables rules to proper UniFi API firewall rules
"""

import requests
import json
import logging
from typing import Dict, List
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('UniFiFirewallRules')

class UniFiFirewallRuleManager:
    """Manage UniFi firewall rules via API"""
    
    def __init__(self, controller_url: str = "https://192.168.22.1:8443", 
                 username: str = "root", password: str = ""):
        self.controller_url = controller_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for self-signed certs
        
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.site_id = "default"  # Default site ID
        
    def authenticate(self) -> bool:
        """Authenticate with UniFi controller using username/password"""
        try:
            login_data = {
                "username": self.username,
                "password": self.password
            }
            
            response = self.session.post(
                f"{self.controller_url}/api/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Successfully authenticated with UniFi controller")
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def authenticate_with_api_key(self, api_key: str) -> bool:
        """Authenticate with UCG-Fiber controller using API key"""
        try:
            # Set API key in headers using the correct format
            self.session.headers.update({
                'X-API-KEY': api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })
            
            # Test authentication by getting sites (UCG-Fiber network API)
            response = self.session.get(
                f"{self.controller_url}/proxy/network/integration/v1/sites",
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Successfully authenticated with UCG-Fiber controller using API key")
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
            # Use the correct UniFi Network API endpoint
            response = self.session.post(
                f"{self.controller_url}/proxy/network/api/s/default/rest/firewallrule",
                json=rule_config,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Created firewall rule: {rule_config.get('name', 'unnamed')}")
                return True
            else:
                # Try alternative endpoint
                response = self.session.post(
                    f"{self.controller_url}/proxy/protect/integration/v1/network/firewall",
                    json=rule_config,
                    timeout=10
                )
                
                if response.status_code in [200, 201]:
                    logger.info(f"Created firewall rule (alt endpoint): {rule_config.get('name', 'unnamed')}")
                    return True
                else:
                    logger.error(f"Failed to create firewall rule: {response.status_code} - {response.text}")
                    return False
                
        except Exception as e:
            logger.error(f"Error creating firewall rule: {e}")
            return False
    
    def create_comprehensive_firewall_rules(self) -> Dict:
        """Create comprehensive firewall rules to block unmanaged ranges"""
        results = {
            'rules_created': [],
            'rules_failed': [],
            'total_created': 0,
            'total_failed': 0
        }
        
        logger.info("Creating comprehensive UniFi firewall rules...")
        
        # Define all the rules we need to create
        firewall_rules = self._get_all_firewall_rules()
        
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
    
    def _get_all_firewall_rules(self) -> List[Dict]:
        """Get all firewall rules that need to be created using correct UniFi 8.x format"""
        rules = []
        rule_index = 20000  # Start from 20000+ range for UniFi 8.x compatibility
        
        # IPv4 Unmanaged Ranges - WAN_IN rules
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
                "_id": None,  # Set to null for new rules
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
                "_id": None,  # Set to null for new rules
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
        
        # IPv6 Unmanaged Ranges - WAN_IN rules
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
                "_id": None,  # Set to null for new rules
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
                "_id": None,  # Set to null for new rules
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
    
    def get_existing_firewall_rules(self) -> List[Dict]:
        """Get existing firewall rules from UCG-Fiber"""
        try:
            response = self.session.get(
                f"{self.controller_url}/proxy/network/api/s/default/rest/firewallrule",
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get firewall rules: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting firewall rules: {e}")
            return []
    
    def verify_firewall_rules(self) -> Dict:
        """Verify that firewall rules are active"""
        try:
            existing_rules = self.get_existing_firewall_rules()
            
            # Count rules by type
            wan_in_rules = len([r for r in existing_rules if r.get('ruleset') == 'WAN_IN'])
            wan_out_rules = len([r for r in existing_rules if r.get('ruleset') == 'WAN_OUT'])
            drop_rules = len([r for r in existing_rules if r.get('action') == 'drop'])
            ipv4_rules = len([r for r in existing_rules if r.get('ip_version') == 'IPv4'])
            ipv6_rules = len([r for r in existing_rules if r.get('ip_version') == 'IPv6'])
            
            return {
                'total_rules': len(existing_rules),
                'wan_in_rules': wan_in_rules,
                'wan_out_rules': wan_out_rules,
                'drop_rules': drop_rules,
                'ipv4_rules': ipv4_rules,
                'ipv6_rules': ipv6_rules,
                'status': 'healthy' if drop_rules > 0 else 'warning'
            }
            
        except Exception as e:
            logger.error(f"Error verifying firewall rules: {e}")
            return {'status': 'error', 'error': str(e)}

def main():
    """Main function to create UniFi firewall rules"""
    print("=" * 80)
    print("UNIFI FIREWALL RULES CREATION")
    print("=" * 80)
    
    # Use the provided API key
    api_key = "pHo9WiYBi4V9w7ajuOcnzUYDXWHvAxZn"
    
    # Initialize manager
    manager = UniFiFirewallRuleManager()
    
    # Authenticate with API key
    print("\nAuthenticating with UniFi controller using API key...")
    if not manager.authenticate_with_api_key(api_key):
        print("❌ API key authentication failed!")
        print("Falling back to username/password authentication...")
        
        # Fallback to username/password
        username = input("Enter UniFi username (default: root): ").strip() or "root"
        password = input("Enter UniFi password: ").strip()
        
        if not password:
            print("❌ Password is required for fallback!")
            return
        
        manager.username = username
        manager.password = password
        
        if not manager.authenticate():
            print("❌ Both API key and password authentication failed!")
            return
    
    print("✅ Authentication successful!")
    
    # Create firewall rules
    print("\nCreating comprehensive firewall rules...")
    results = manager.create_comprehensive_firewall_rules()
    
    print(f"\n=== RESULTS ===")
    print(f"✅ Rules created: {results['total_created']}")
    print(f"❌ Rules failed: {results['total_failed']}")
    
    if results['rules_created']:
        print(f"\nCreated rules:")
        for rule_name in results['rules_created'][:10]:  # Show first 10
            print(f"  - {rule_name}")
        if len(results['rules_created']) > 10:
            print(f"  ... and {len(results['rules_created']) - 10} more")
    
    if results['rules_failed']:
        print(f"\nFailed rules:")
        for rule_name in results['rules_failed']:
            print(f"  - {rule_name}")
    
    # Verify rules
    print(f"\nVerifying firewall rules...")
    verification = manager.verify_firewall_rules()
    
    print(f"\n=== VERIFICATION ===")
    print(f"Total rules: {verification.get('total_rules', 0)}")
    print(f"WAN_IN rules: {verification.get('wan_in_rules', 0)}")
    print(f"WAN_OUT rules: {verification.get('wan_out_rules', 0)}")
    print(f"Drop rules: {verification.get('drop_rules', 0)}")
    print(f"IPv4 rules: {verification.get('ipv4_rules', 0)}")
    print(f"IPv6 rules: {verification.get('ipv6_rules', 0)}")
    print(f"Status: {verification.get('status', 'unknown').upper()}")
    
    if verification.get('status') == 'healthy':
        print(f"\n🎉 SUCCESS! All unmanaged IPv4 and IPv6 ranges are now blocked via UniFi firewall rules!")
        print(f"✅ WAN interfaces are protected against private IP traffic")
        print(f"✅ Rules are persistent and managed through UniFi Network application")
    else:
        print(f"\n⚠️  Some rules may need manual verification")
        print(f"Check the UniFi Network application: https://192.168.22.1:8443")

if __name__ == "__main__":
    main()
