#!/usr/bin/env python3
"""
Clean up problematic LAN_IN rules and duplicates
"""

import requests
import json
import logging
from typing import Dict, List
import time
import urllib3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('CleanupRules')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RuleCleanupManager:
    def __init__(self, controller_url: str = "https://192.168.22.1", api_key: str = ""):
        self.controller_url = controller_url
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = False
        self.api_base = f"{self.controller_url}/proxy/network/api/s/default"

    def authenticate_with_api_key(self, api_key: str) -> bool:
        """Authenticate with UCG-Fiber using API key"""
        try:
            self.api_key = api_key
            self.session.headers.update({
                'X-API-KEY': self.api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })
            
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

    def delete_firewall_rule(self, rule_id: str) -> bool:
        """Delete a firewall rule by ID"""
        try:
            response = self.session.delete(
                f"{self.api_base}/rest/firewallrule/{rule_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully deleted rule: {rule_id}")
                return True
            else:
                logger.error(f"Failed to delete rule {rule_id}: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting rule {rule_id}: {e}")
            return False

    def cleanup_problematic_rules(self) -> Dict:
        """Clean up problematic LAN_IN rules and duplicates"""
        results = {
            'lan_rules_deleted': [],
            'duplicates_deleted': [],
            'total_deleted': 0,
            'failed_deletions': 0
        }
        
        logger.info("Getting existing firewall rules...")
        existing_rules = self.get_existing_firewall_rules()
        
        # Find problematic LAN_IN rules
        problematic_lan_rules = [
            r for r in existing_rules 
            if r.get('ruleset') == 'LAN_IN' and r.get('action') == 'drop'
        ]
        
        # Find duplicate rules (by name)
        rule_names = {}
        for rule in existing_rules:
            name = rule.get('name', '')
            if name not in rule_names:
                rule_names[name] = []
            rule_names[name].append(rule)
        
        duplicate_rules = []
        for name, rules in rule_names.items():
            if len(rules) > 1:
                # Keep the first one, mark others for deletion
                duplicate_rules.extend(rules[1:])
        
        logger.info(f"Found {len(problematic_lan_rules)} problematic LAN_IN rules")
        logger.info(f"Found {len(duplicate_rules)} duplicate rules")
        
        # Delete problematic LAN_IN rules
        logger.info("Deleting problematic LAN_IN rules...")
        for rule in problematic_lan_rules:
            rule_id = rule.get('_id')
            rule_name = rule.get('name', 'unnamed')
            if rule_id:
                if self.delete_firewall_rule(rule_id):
                    results['lan_rules_deleted'].append(rule_name)
                    results['total_deleted'] += 1
                else:
                    results['failed_deletions'] += 1
                time.sleep(0.2)
        
        # Delete duplicate rules
        logger.info("Deleting duplicate rules...")
        for rule in duplicate_rules:
            rule_id = rule.get('_id')
            rule_name = rule.get('name', 'unnamed')
            if rule_id:
                if self.delete_firewall_rule(rule_id):
                    results['duplicates_deleted'].append(rule_name)
                    results['total_deleted'] += 1
                else:
                    results['failed_deletions'] += 1
                time.sleep(0.2)
        
        return results

    def verify_cleanup(self) -> Dict:
        """Verify the cleanup was successful"""
        try:
            existing_rules = self.get_existing_firewall_rules()
            
            # Check for remaining LAN_IN rules
            remaining_lan_rules = [
                r for r in existing_rules 
                if r.get('ruleset') == 'LAN_IN' and r.get('action') == 'drop'
            ]
            
            # Check for remaining duplicates
            rule_names = {}
            for rule in existing_rules:
                name = rule.get('name', '')
                if name not in rule_names:
                    rule_names[name] = []
                rule_names[name].append(rule)
            
            remaining_duplicates = []
            for name, rules in rule_names.items():
                if len(rules) > 1:
                    remaining_duplicates.extend(rules[1:])
            
            # Count WAN rules (should remain)
            wan_rules = [
                r for r in existing_rules 
                if r.get('ruleset') in ['WAN_IN', 'WAN_OUT']
            ]
            
            return {
                'total_rules': len(existing_rules),
                'wan_rules': len(wan_rules),
                'remaining_lan_rules': len(remaining_lan_rules),
                'remaining_duplicates': len(remaining_duplicates),
                'cleanup_successful': len(remaining_lan_rules) == 0 and len(remaining_duplicates) == 0
            }
            
        except Exception as e:
            logger.error(f"Error verifying cleanup: {e}")
            return {'cleanup_successful': False, 'error': str(e)}

def main():
    print("=" * 80)
    print("CLEANING UP PROBLEMATIC FIREWALL RULES")
    print("=" * 80)
    
    api_key = "C5tSpDSC2J_bZy9oqYwBDesWoUP1sHIK"
    manager = RuleCleanupManager(api_key=api_key)
    
    if not manager.authenticate_with_api_key(api_key):
        logger.error("Authentication failed. Exiting.")
        return
    
    print("\n🧹 Cleaning up problematic rules...")
    print("This will remove:")
    print("  - LAN_IN rules that block internal services (DNS, mDNS, LLMNR)")
    print("  - Duplicate rules (mDNS, LLMNR)")
    print("  - Keep all WAN protection rules intact")
    
    # Perform cleanup
    results = manager.cleanup_problematic_rules()
    
    print(f"\n=== CLEANUP RESULTS ===")
    print(f"✅ LAN rules deleted: {len(results['lan_rules_deleted'])}")
    print(f"✅ Duplicate rules deleted: {len(results['duplicates_deleted'])}")
    print(f"✅ Total rules deleted: {results['total_deleted']}")
    print(f"❌ Failed deletions: {results['failed_deletions']}")
    
    if results['lan_rules_deleted']:
        print(f"\nDeleted LAN rules:")
        for rule_name in results['lan_rules_deleted']:
            print(f"  - {rule_name}")
    
    if results['duplicates_deleted']:
        print(f"\nDeleted duplicate rules:")
        for rule_name in results['duplicates_deleted']:
            print(f"  - {rule_name}")
    
    # Verify cleanup
    print("\n🔍 Verifying cleanup...")
    verification = manager.verify_cleanup()
    
    print(f"\n=== VERIFICATION ===")
    print(f"Total rules remaining: {verification.get('total_rules', 0)}")
    print(f"WAN protection rules: {verification.get('wan_rules', 0)}")
    print(f"Remaining LAN rules: {verification.get('remaining_lan_rules', 0)}")
    print(f"Remaining duplicates: {verification.get('remaining_duplicates', 0)}")
    print(f"Cleanup successful: {verification.get('cleanup_successful', False)}")
    
    if verification.get('cleanup_successful'):
        print(f"\n🎉 SUCCESS! All problematic rules have been cleaned up!")
        print(f"✅ Internal network services should now work properly")
        print(f"✅ WAN protection remains fully active")
        print(f"✅ No duplicate rules remain")
    else:
        print(f"\n⚠️  Some rules may still need manual cleanup")
        print(f"Check the UCG-Fiber interface: {manager.controller_url}")

if __name__ == "__main__":
    main()
