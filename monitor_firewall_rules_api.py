#!/usr/bin/env python3
"""
Monitor UniFi Firewall Rules API for new rules created via UI

This script will monitor the firewall rules endpoint to detect when
a new rule is created via the web interface, allowing us to see
the exact field format used by the system.
"""

import requests
import json
import logging
from typing import Dict, List, Set
import time
import urllib3
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('FirewallRuleMonitor')

class FirewallRuleMonitor:
    def __init__(self, controller_url: str = "https://192.168.22.1", api_key: str = ""):
        self.controller_url = controller_url
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = False
        
        # API endpoints
        self.api_base = f"{self.controller_url}/proxy/network/api/s/default"
        self.firewall_rules_endpoint = f"{self.api_base}/rest/firewallrule"
        
        # Set up session headers
        self.session.headers.update({
            'X-API-KEY': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # Track existing rules
        self.known_rule_ids: Set[str] = set()
        
    def authenticate_with_api_key(self, api_key: str) -> bool:
        """Authenticate with UCG-Fiber using API key"""
        try:
            self.api_key = api_key
            self.session.headers.update({
                'X-API-KEY': self.api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })
            
            # Test authentication by getting firewall rules
            response = self.session.get(
                self.firewall_rules_endpoint,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("✅ Successfully authenticated with UCG-Fiber using API key")
                return True
            else:
                logger.error(f"❌ API key authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"❌ API key authentication error: {e}")
            return False
    
    def get_firewall_rules(self) -> List[Dict]:
        """Get current firewall rules from the API"""
        try:
            response = self.session.get(self.firewall_rules_endpoint, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                logger.error(f"Failed to get firewall rules: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"Error getting firewall rules: {e}")
            return []
    
    def initialize_known_rules(self):
        """Initialize the set of known rule IDs"""
        rules = self.get_firewall_rules()
        self.known_rule_ids = {rule.get('_id', '') for rule in rules if rule.get('_id')}
        logger.info(f"Initialized with {len(self.known_rule_ids)} existing rules")
    
    def detect_new_rules(self) -> List[Dict]:
        """Detect any new firewall rules"""
        current_rules = self.get_firewall_rules()
        current_rule_ids = {rule.get('_id', '') for rule in current_rules if rule.get('_id')}
        
        new_rule_ids = current_rule_ids - self.known_rule_ids
        new_rules = [rule for rule in current_rules if rule.get('_id') in new_rule_ids]
        
        # Update known rule IDs
        self.known_rule_ids = current_rule_ids
        
        return new_rules
    
    def analyze_rule_structure(self, rule: Dict) -> Dict:
        """Analyze the structure of a firewall rule"""
        analysis = {
            'rule_id': rule.get('_id', 'Unknown'),
            'name': rule.get('name', 'Unknown'),
            'fields': list(rule.keys()),
            'field_types': {key: type(value).__name__ for key, value in rule.items()},
            'sample_values': {key: str(value)[:100] for key, value in rule.items()},
            'timestamp': datetime.now().isoformat()
        }
        return analysis
    
    def save_rule_analysis(self, rule: Dict, analysis: Dict):
        """Save the rule analysis to a file"""
        filename = f"firewall_rule_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        data = {
            'original_rule': rule,
            'analysis': analysis,
            'discovery_timestamp': datetime.now().isoformat()
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"✅ Rule analysis saved to {filename}")
        except Exception as e:
            logger.error(f"❌ Failed to save rule analysis: {e}")
    
    def monitor_for_new_rules(self, duration_minutes: int = 10):
        """Monitor for new firewall rules for specified duration"""
        logger.info(f"🔍 Starting firewall rule monitoring for {duration_minutes} minutes...")
        logger.info("📝 Please create a firewall rule in the UniFi web interface now!")
        logger.info("🌐 Access the web interface at: https://192.168.22.1/network")
        logger.info("🔧 Go to: Settings > Security > Firewall > Traffic Rules")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        check_interval = 5  # Check every 5 seconds
        last_check_time = start_time
        
        while time.time() < end_time:
            try:
                # Check for new rules
                new_rules = self.detect_new_rules()
                
                if new_rules:
                    logger.info(f"🎉 DETECTED {len(new_rules)} NEW FIREWALL RULE(S)!")
                    
                    for rule in new_rules:
                        logger.info(f"📋 New Rule: {rule.get('name', 'Unnamed')}")
                        logger.info(f"🆔 Rule ID: {rule.get('_id', 'Unknown')}")
                        
                        # Analyze the rule structure
                        analysis = self.analyze_rule_structure(rule)
                        
                        logger.info(f"📊 Rule Analysis:")
                        logger.info(f"  Fields: {analysis['fields']}")
                        logger.info(f"  Field Types: {analysis['field_types']}")
                        
                        # Save detailed analysis
                        self.save_rule_analysis(rule, analysis)
                        
                        # Print the full rule structure
                        logger.info(f"📄 Full Rule Structure:")
                        print(json.dumps(rule, indent=2))
                        
                        logger.info("=" * 80)
                
                # Wait for next check
                time.sleep(check_interval)
                
                # Show progress every 30 seconds
                if time.time() - last_check_time >= 30:
                    remaining_minutes = int((end_time - time.time()) / 60)
                    logger.info(f"⏰ Monitoring... {remaining_minutes} minutes remaining")
                    last_check_time = time.time()
                    
            except KeyboardInterrupt:
                logger.info("🛑 Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"❌ Error during monitoring: {e}")
                time.sleep(check_interval)
        
        logger.info("🏁 Monitoring completed")
        
        # Final check for any rules that might have been missed
        final_new_rules = self.detect_new_rules()
        if final_new_rules:
            logger.info(f"📋 Final check found {len(final_new_rules)} additional new rules")
            for rule in final_new_rules:
                analysis = self.analyze_rule_structure(rule)
                self.save_rule_analysis(rule, analysis)
                print(json.dumps(rule, indent=2))

def main():
    print("=" * 80)
    print("UNIFI FIREWALL RULES API MONITOR")
    print("=" * 80)
    print("This script will monitor the UniFi API for new firewall rules")
    print("created via the web interface to discover the correct field format.")
    print("=" * 80)
    
    # Use the working API key
    api_key = "C5tSpDSC2J_bZy9oqYwBDesWoUP1sHIK"
    monitor = FirewallRuleMonitor(api_key=api_key)
    
    print("\n🔐 Authenticating with UCG-Fiber using API key...")
    if not monitor.authenticate_with_api_key(api_key):
        print("❌ API key authentication failed!")
        return
    
    print("✅ Authentication successful!")
    
    # Initialize with current rules
    print("\n📊 Initializing rule monitoring...")
    monitor.initialize_known_rules()
    
    # Start monitoring
    print("\n🚀 Starting monitoring process...")
    print("📝 INSTRUCTIONS:")
    print("1. Open your web browser")
    print("2. Go to: https://192.168.22.1/network")
    print("3. Navigate to: Settings > Security > Firewall > Traffic Rules")
    print("4. Create a new firewall rule (any simple rule will do)")
    print("5. Save the rule")
    print("6. The script will detect it and show the field format!")
    print()
    
    try:
        monitor.monitor_for_new_rules(duration_minutes=15)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user")
    
    print("\n🎯 MONITORING COMPLETE!")
    print("📄 Check the generated JSON files for detailed rule structure analysis")
    print("🔧 Use the discovered field format to create API-based firewall rules")

if __name__ == "__main__":
    main()
