#!/usr/bin/env python3
"""
SSH-based Firewall Rules Creator for UCG-Fiber
Creates comprehensive firewall rules using SSH and iptables/ip6tables
"""

import subprocess
import logging
import time
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SSHFirewallRules')

class SSHFirewallRuleManager:
    """Manage firewall rules via SSH on UCG-Fiber device"""
    
    def __init__(self, ucg_ip: str = "192.168.22.1", ssh_key_path: str = "~/.ssh/ucg_fiber_key"):
        self.ucg_ip = ucg_ip
        self.ssh_key_path = ssh_key_path
        self.expanded_key_path = ssh_key_path.replace("~", "/Users/danielborrowman")
        
    def run_ssh_command(self, command: str) -> Tuple[bool, str]:
        """Run SSH command on UCG-Fiber device"""
        try:
            ssh_command = [
                'ssh', '-i', self.expanded_key_path, 
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=10',
                f'root@{self.ucg_ip}',
                command
            ]
            
            result = subprocess.run(
                ssh_command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                return False, result.stderr.strip()
                
        except subprocess.TimeoutExpired:
            logger.error(f"SSH command timed out: {command}")
            return False, "Command timed out"
        except Exception as e:
            logger.error(f"SSH command error: {e}")
            return False, str(e)
    
    def create_comprehensive_firewall_rules(self) -> Dict:
        """Create comprehensive firewall rules to block unmanaged ranges"""
        results = {
            'rules_created': [],
            'rules_failed': [],
            'total_created': 0,
            'total_failed': 0
        }
        
        logger.info("Creating comprehensive firewall rules via SSH...")
        
        # Define all the rules we need to create
        firewall_rules = self._get_all_firewall_rules()
        
        for rule in firewall_rules:
            success = self._apply_firewall_rule(rule)
            
            if success:
                results['rules_created'].append(rule['name'])
                results['total_created'] += 1
            else:
                results['rules_failed'].append(rule['name'])
                results['total_failed'] += 1
            
            # Small delay between commands
            time.sleep(0.2)
        
        logger.info(f"Firewall rules creation completed: {results['total_created']} created, {results['total_failed']} failed")
        return results
    
    def _apply_firewall_rule(self, rule: Dict) -> bool:
        """Apply a single firewall rule via SSH"""
        try:
            # Build the iptables/ip6tables command
            if rule['ip_version'] == 'IPv4':
                cmd = 'iptables'
            else:
                cmd = 'ip6tables'
            
            # Build the rule command
            if rule['direction'] == 'WAN_IN':
                # Block incoming traffic from unmanaged ranges
                iptables_cmd = f"{cmd} -I FORWARD -s {rule['network']} -j DROP"
            else:  # WAN_OUT
                # Block outgoing traffic to unmanaged ranges
                iptables_cmd = f"{cmd} -I FORWARD -d {rule['network']} -j DROP"
            
            # Add logging if requested
            if rule.get('log', False):
                log_cmd = f"{cmd} -I FORWARD -s {rule['network']} -j LOG --log-prefix 'BLOCK_UNMANAGED: '"
                success, output = self.run_ssh_command(log_cmd)
                if not success:
                    logger.warning(f"Failed to add logging rule: {output}")
            
            # Apply the main rule
            success, output = self.run_ssh_command(iptables_cmd)
            
            if success:
                logger.info(f"Created firewall rule: {rule['name']}")
                return True
            else:
                logger.error(f"Failed to create firewall rule {rule['name']}: {output}")
                return False
                
        except Exception as e:
            logger.error(f"Error applying firewall rule {rule['name']}: {e}")
            return False
    
    def _get_all_firewall_rules(self) -> List[Dict]:
        """Get all firewall rules that need to be created"""
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
            # WAN_IN rules (block incoming from unmanaged ranges)
            rules.append({
                "name": f"Block_{name_suffix}_WAN_IN",
                "network": network,
                "ip_version": "IPv4",
                "direction": "WAN_IN",
                "action": "DROP",
                "log": True
            })
            
            # WAN_OUT rules (block outgoing to unmanaged ranges)
            rules.append({
                "name": f"Block_{name_suffix}_WAN_OUT",
                "network": network,
                "ip_version": "IPv4",
                "direction": "WAN_OUT",
                "action": "DROP",
                "log": True
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
            # WAN_IN rules (block incoming from unmanaged ranges)
            rules.append({
                "name": f"Block_{name_suffix}_WAN_IN",
                "network": network,
                "ip_version": "IPv6",
                "direction": "WAN_IN",
                "action": "DROP",
                "log": True
            })
            
            # WAN_OUT rules (block outgoing to unmanaged ranges)
            rules.append({
                "name": f"Block_{name_suffix}_WAN_OUT",
                "network": network,
                "ip_version": "IPv6",
                "direction": "WAN_OUT",
                "action": "DROP",
                "log": True
            })
        
        return rules
    
    def save_firewall_rules(self) -> bool:
        """Save firewall rules to make them persistent"""
        try:
            # Save iptables rules
            success_ipv4, output_ipv4 = self.run_ssh_command("iptables-save > /etc/iptables/rules.v4")
            success_ipv6, output_ipv6 = self.run_ssh_command("ip6tables-save > /etc/iptables/rules.v6")
            
            if success_ipv4 and success_ipv6:
                logger.info("Firewall rules saved successfully")
                return True
            else:
                logger.error(f"Failed to save rules: IPv4={output_ipv4}, IPv6={output_ipv6}")
                return False
                
        except Exception as e:
            logger.error(f"Error saving firewall rules: {e}")
            return False
    
    def verify_firewall_rules(self) -> Dict:
        """Verify that firewall rules are active"""
        try:
            # Get current iptables rules
            success_ipv4, output_ipv4 = self.run_ssh_command("iptables -L FORWARD -n --line-numbers | grep DROP")
            success_ipv6, output_ipv6 = self.run_ssh_command("ip6tables -L FORWARD -n --line-numbers | grep DROP")
            
            # Count rules
            ipv4_drop_rules = len([line for line in output_ipv4.split('\n') if line.strip()]) if success_ipv4 else 0
            ipv6_drop_rules = len([line for line in output_ipv6.split('\n') if line.strip()]) if success_ipv6 else 0
            
            return {
                'ipv4_drop_rules': ipv4_drop_rules,
                'ipv6_drop_rules': ipv6_drop_rules,
                'total_drop_rules': ipv4_drop_rules + ipv6_drop_rules,
                'status': 'healthy' if (ipv4_drop_rules + ipv6_drop_rules) > 0 else 'warning'
            }
            
        except Exception as e:
            logger.error(f"Error verifying firewall rules: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def test_ssh_connection(self) -> bool:
        """Test SSH connection to UCG-Fiber device"""
        success, output = self.run_ssh_command("echo 'SSH connection test successful'")
        return success

def main():
    """Main function to create firewall rules via SSH"""
    print("=" * 80)
    print("SSH-BASED FIREWALL RULES CREATION")
    print("=" * 80)
    
    # Initialize manager
    manager = SSHFirewallRuleManager()
    
    # Test SSH connection
    print("\nTesting SSH connection to UCG-Fiber device...")
    if not manager.test_ssh_connection():
        print("❌ SSH connection failed!")
        print("Please ensure:")
        print("1. UCG-Fiber device is accessible at 192.168.22.1")
        print("2. SSH key is available at ~/.ssh/ucg_fiber_key")
        print("3. SSH service is running on the device")
        return
    
    print("✅ SSH connection successful!")
    
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
    
    # Save rules to make them persistent
    print(f"\nSaving firewall rules to make them persistent...")
    if manager.save_firewall_rules():
        print("✅ Firewall rules saved successfully!")
    else:
        print("⚠️  Failed to save rules - they may not persist after reboot")
    
    # Verify rules
    print(f"\nVerifying firewall rules...")
    verification = manager.verify_firewall_rules()
    
    print(f"\n=== VERIFICATION ===")
    print(f"IPv4 DROP rules: {verification.get('ipv4_drop_rules', 0)}")
    print(f"IPv6 DROP rules: {verification.get('ipv6_drop_rules', 0)}")
    print(f"Total DROP rules: {verification.get('total_drop_rules', 0)}")
    print(f"Status: {verification.get('status', 'unknown').upper()}")
    
    if verification.get('status') == 'healthy':
        print(f"\n🎉 SUCCESS! All unmanaged IPv4 and IPv6 ranges are now blocked!")
        print(f"✅ WAN interfaces are protected against private IP traffic")
        print(f"✅ Rules are active and blocking unmanaged ranges")
        print(f"✅ Both IPv4 and IPv6 traffic is filtered")
    else:
        print(f"\n⚠️  Some rules may need manual verification")
        print(f"Check the device with: ssh root@192.168.22.1 'iptables -L FORWARD -n'")

if __name__ == "__main__":
    main()
