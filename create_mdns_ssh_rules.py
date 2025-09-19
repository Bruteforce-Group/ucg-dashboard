#!/usr/bin/env python3
"""
Create mDNS and Multicast SSH Rules for LAN (192.168.22.x)
Uses SSH to directly add iptables rules for mDNS and multicast on managed networks
"""

import subprocess
import time
from datetime import datetime

class SSHmDNSRuleCreator:
    def __init__(self, host="192.168.22.1", ssh_key="~/.ssh/ucg_fiber_key"):
        self.host = host
        self.ssh_key = ssh_key
        
    def run_ssh_command(self, command):
        """Run SSH command and return result"""
        try:
            cmd = [
                "ssh", "-i", self.ssh_key, 
                "-o", "StrictHostKeyChecking=no",
                f"root@{self.host}",
                command
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def create_mdns_rules(self):
        """Create mDNS and multicast rules via SSH"""
        
        print("🔧 Creating mDNS and Multicast SSH Rules")
        print("=" * 50)
        
        # Define the rules to create
        rules = [
            # mDNS rules (port 5353)
            {
                "name": "Allow mDNS LAN_IN",
                "command": "iptables -I UBIOS_LAN_IN_USER 1 -s 192.168.22.0/24 -d 224.0.0.251 -p udp --dport 5353 -j ACCEPT -m comment --comment 'Allow_mDNS_LAN_IN'"
            },
            {
                "name": "Allow mDNS LAN_OUT", 
                "command": "iptables -I UBIOS_LAN_OUT_USER 1 -s 192.168.22.0/24 -d 224.0.0.251 -p udp --dport 5353 -j ACCEPT -m comment --comment 'Allow_mDNS_LAN_OUT'"
            },
            
            # LLMNR rules (port 5355)
            {
                "name": "Allow LLMNR LAN_IN",
                "command": "iptables -I UBIOS_LAN_IN_USER 1 -s 192.168.22.0/24 -d 224.0.0.252 -p udp --dport 5355 -j ACCEPT -m comment --comment 'Allow_LLMNR_LAN_IN'"
            },
            {
                "name": "Allow LLMNR LAN_OUT",
                "command": "iptables -I UBIOS_LAN_OUT_USER 1 -s 192.168.22.0/24 -d 224.0.0.252 -p udp --dport 5355 -j ACCEPT -m comment --comment 'Allow_LLMNR_LAN_OUT'"
            },
            
            # General multicast rules
            {
                "name": "Allow Multicast LAN_IN",
                "command": "iptables -I UBIOS_LAN_IN_USER 1 -s 192.168.22.0/24 -d 224.0.0.0/4 -p udp -j ACCEPT -m comment --comment 'Allow_Multicast_LAN_IN'"
            },
            {
                "name": "Allow Multicast LAN_OUT",
                "command": "iptables -I UBIOS_LAN_OUT_USER 1 -s 192.168.22.0/24 -d 224.0.0.0/4 -p udp -j ACCEPT -m comment --comment 'Allow_Multicast_LAN_OUT'"
            },
            
            # IPv6 mDNS rules
            {
                "name": "Allow IPv6 mDNS LAN_IN",
                "command": "ip6tables -I UBIOS_LAN_IN_USER 1 -s 2001:db8::/32 -d ff02::fb -p udp --dport 5353 -j ACCEPT -m comment --comment 'Allow_IPv6_mDNS_LAN_IN'"
            },
            {
                "name": "Allow IPv6 mDNS LAN_OUT",
                "command": "ip6tables -I UBIOS_LAN_OUT_USER 1 -s 2001:db8::/32 -d ff02::fb -p udp --dport 5353 -j ACCEPT -m comment --comment 'Allow_IPv6_mDNS_LAN_OUT'"
            }
        ]
        
        created_rules = []
        failed_rules = []
        
        for rule in rules:
            print(f"Creating: {rule['name']}")
            success, stdout, stderr = self.run_ssh_command(rule['command'])
            
            if success:
                created_rules.append(rule['name'])
                print(f"✅ Created: {rule['name']}")
            else:
                failed_rules.append(f"{rule['name']}: {stderr}")
                print(f"❌ Failed: {rule['name']} - {stderr}")
            
            time.sleep(0.5)  # Rate limiting
        
        return created_rules, failed_rules
    
    def verify_rules(self):
        """Verify the rules were created successfully"""
        print("\n🔍 Verifying Rules...")
        
        # Check IPv4 mDNS rules
        success, stdout, stderr = self.run_ssh_command("iptables -L -n | grep -E '(Allow_mDNS|Allow_LLMNR|Allow_Multicast)'")
        if success and stdout:
            print("✅ IPv4 mDNS/Multicast rules found:")
            for line in stdout.strip().split('\n'):
                if line.strip():
                    print(f"   {line}")
        else:
            print("❌ No IPv4 mDNS/Multicast rules found")
        
        # Check IPv6 mDNS rules
        success, stdout, stderr = self.run_ssh_command("ip6tables -L -n | grep -E '(Allow_IPv6_mDNS)'")
        if success and stdout:
            print("✅ IPv6 mDNS rules found:")
            for line in stdout.strip().split('\n'):
                if line.strip():
                    print(f"   {line}")
        else:
            print("❌ No IPv6 mDNS rules found")

def main():
    print("🔧 UCG mDNS SSH Rules Creator")
    print("=" * 50)
    
    creator = SSHmDNSRuleCreator()
    
    print("Creating mDNS and multicast ALLOW rules via SSH...")
    created, failed = creator.create_mdns_rules()
    
    print("\n📊 RESULTS:")
    print(f"✅ Created: {len(created)} rules")
    for rule in created:
        print(f"   - {rule}")
    
    if failed:
        print(f"❌ Failed: {len(failed)} rules")
        for rule in failed:
            print(f"   - {rule}")
    
    # Verify rules
    creator.verify_rules()
    
    print("\n🎯 These rules will allow:")
    print("   - mDNS (port 5353) on 192.168.22.x")
    print("   - LLMNR (port 5355) on 192.168.22.x") 
    print("   - General multicast (224.0.0.0/4) on 192.168.22.x")
    print("   - IPv6 mDNS (ff02::fb) on managed networks")
    print("   - Both LAN_IN and LAN_OUT directions")

if __name__ == "__main__":
    main()
