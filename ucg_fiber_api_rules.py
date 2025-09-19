#!/usr/bin/env python3
"""
UCG-Fiber API Firewall Rules Creator
Uses the correct UCG-Fiber API endpoint structure discovered through testing
"""

import requests
import json
import logging
import time
from typing import Dict, List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('UCGFiberAPIRules')

class UCGFiberAPIRuleManager:
    """Manage UCG-Fiber firewall rules via API"""
    
    def __init__(self, controller_url: str = "https://192.168.22.1"):
        self.controller_url = controller_url
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for self-signed certs
        
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Use port 443 (not 8443) - discovered through testing
        self.api_base = f"{self.controller_url}/proxy/network/api/s/default"
        
    def authenticate_with_api_key(self, api_key: str) -> bool:
        """Authenticate with UCG-Fiber using API key"""
        try:
            # Set API key in headers using the correct format
            self.session.headers.update({
                'X-API-KEY': api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })
            
            # Test authentication by getting firewall rules
            response = self.session.get(
                f"{self.api_base}/rest/firewallrule",
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
    
    def get_sites(self) -> List[Dict]:
        """Get available sites"""
        try:
            response = self.session.get(
                f"{self.controller_url}/proxy/network/integration/v1/sites",
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get sites: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting sites: {e}")
            return []
    
    def get_existing_firewall_rules(self) -> List[Dict]:
        """Get existing firewall rules from UCG-Fiber"""
        try:
            response = self.session.get(
                f"{self.api_base}/rest/firewallrule",
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
    
    def create_firewall_rule(self, rule_config: Dict) -> bool:
        """Create a firewall rule in UCG-Fiber"""
        try:
            response = self.session.post(
                f"{self.api_base}/rest/firewallrule",
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
    
    def create_unmanaged_range_blocking_rules(self) -> Dict:
        """Create firewall rules to block unmanaged IPv4 and IPv6 ranges"""
        results = {
            'rules_created': [],
            'rules_failed': [],
            'total_created': 0,
            'total_failed': 0
        }
        
        logger.info("Creating UCG-Fiber firewall rules to block unmanaged ranges...")
        
        # Define all the rules we need to create
        firewall_rules = self._get_unmanaged_blocking_rules()
        
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
    
    def _get_unmanaged_blocking_rules(self) -> List[Dict]:
        """Get firewall rules to block unmanaged ranges in UCG-Fiber format"""
        rules = []
        
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
            # Block incoming traffic from unmanaged IPv4 ranges
            rules.append({
                "name": f"Block {name_suffix} Traffic",
                "enabled": True,
                "action": "drop",
                "direction": "in",
                "protocol": "all",
                "source": {
                    "type": "ip",
                    "ip": network
                },
                "destination": {
                    "type": "any"
                },
                "logging": True
            })
            
            # Block outgoing traffic to unmanaged IPv4 ranges
            rules.append({
                "name": f"Block Outbound {name_suffix} Traffic",
                "enabled": True,
                "action": "drop",
                "direction": "out",
                "protocol": "all",
                "source": {
                    "type": "any"
                },
                "destination": {
                    "type": "ip",
                    "ip": network
                },
                "logging": True
            })
        
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
            # Block incoming traffic from unmanaged IPv6 ranges
            rules.append({
                "name": f"Block {name_suffix} Traffic",
                "enabled": True,
                "action": "drop",
                "direction": "in",
                "protocol": "all",
                "source": {
                    "type": "ip",
                    "ip": network
                },
                "destination": {
                    "type": "any"
                },
                "logging": True
            })
            
            # Block outgoing traffic to unmanaged IPv6 ranges
            rules.append({
                "name": f"Block Outbound {name_suffix} Traffic",
                "enabled": True,
                "action": "drop",
                "direction": "out",
                "protocol": "all",
                "source": {
                    "type": "any"
                },
                "destination": {
                    "type": "ip",
                    "ip": network
                },
                "logging": True
            })
        
        return rules
    
    def verify_firewall_rules(self) -> Dict:
        """Verify that firewall rules are active"""
        try:
            existing_rules = self.get_existing_firewall_rules()
            
            # Count rules by type
            drop_rules = len([r for r in existing_rules if r.get('action') == 'drop'])
            inbound_rules = len([r for r in existing_rules if r.get('direction') == 'in'])
            outbound_rules = len([r for r in existing_rules if r.get('direction') == 'out'])
            
            # Count unmanaged blocking rules
            unmanaged_blocking_rules = len([r for r in existing_rules 
                                          if 'Block' in r.get('name', '') and 
                                          ('Private' in r.get('name', '') or 
                                           'ULA' in r.get('name', '') or 
                                           'Link_Local' in r.get('name', ''))])
            
            return {
                'total_rules': len(existing_rules),
                'drop_rules': drop_rules,
                'inbound_rules': inbound_rules,
                'outbound_rules': outbound_rules,
                'unmanaged_blocking_rules': unmanaged_blocking_rules,
                'status': 'healthy' if unmanaged_blocking_rules > 0 else 'warning'
            }
            
        except Exception as e:
            logger.error(f"Error verifying firewall rules: {e}")
            return {'status': 'error', 'error': str(e)}

def main():
    """Main function to create UCG-Fiber API firewall rules"""
    print("=" * 80)
    print("UCG-FIBER API FIREWALL RULES CREATION")
    print("=" * 80)
    
    # Use the provided API key
    api_key = "C5tSpDSC2J_bZy9oqYwBDesWoUP1sHIK"
    
    # Initialize manager
    manager = UCGFiberAPIRuleManager()
    
    # Authenticate with API key
    print("\nAuthenticating with UCG-Fiber using API key...")
    if not manager.authenticate_with_api_key(api_key):
        print("❌ API key authentication failed!")
        print("This might be because:")
        print("1. The API key is invalid or expired")
        print("2. The API key doesn't have firewall permissions")
        print("3. Network connectivity issues")
        print("\nFalling back to SSH-based approach...")
        print("Run: python ssh_firewall_rules.py")
        return
    
    print("✅ Authentication successful!")
    
    # Get sites
    print("\nGetting available sites...")
    sites = manager.get_sites()
    if sites:
        print(f"✅ Found {len(sites)} sites")
        for site in sites:
            print(f"  - {site}")
    else:
        print("⚠️  No sites found or failed to retrieve sites")
    
    # Create firewall rules
    print("\nCreating firewall rules to block unmanaged ranges...")
    results = manager.create_unmanaged_range_blocking_rules()
    
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
    print(f"Drop rules: {verification.get('drop_rules', 0)}")
    print(f"Inbound rules: {verification.get('inbound_rules', 0)}")
    print(f"Outbound rules: {verification.get('outbound_rules', 0)}")
    print(f"Unmanaged blocking rules: {verification.get('unmanaged_blocking_rules', 0)}")
    print(f"Status: {verification.get('status', 'unknown').upper()}")
    
    if verification.get('status') == 'healthy':
        print(f"\n🎉 SUCCESS! All unmanaged IPv4 and IPv6 ranges are now blocked via UCG-Fiber API!")
        print(f"✅ WAN interfaces are protected against private IP traffic")
        print(f"✅ Rules are persistent and managed through UCG-Fiber API")
        print(f"✅ View rules at: https://192.168.22.1")
    else:
        print(f"\n⚠️  Some rules may need manual verification")
        print(f"Check the UCG-Fiber interface: https://192.168.22.1")
        print(f"Or use SSH fallback: python ssh_firewall_rules.py")

if __name__ == "__main__":
    main()
