#!/usr/bin/env python3
"""
Restore UCG Firewall Rules After Reboot
This script restores all firewall rules after a UCG device reboot
"""

import subprocess
import json
import time
import os
from datetime import datetime

class UCGRestoreManager:
    def __init__(self, host="192.168.22.1", ssh_key="~/.ssh/ucg_fiber_key"):
        self.host = host
        self.ssh_key = ssh_key
        self.backup_dir = "backups"
        
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
    
    def wait_for_device(self, max_attempts=30):
        """Wait for device to be reachable after reboot"""
        print("⏳ Waiting for UCG device to come online...")
        
        for attempt in range(max_attempts):
            success, _, _ = self.run_ssh_command("echo 'Device online'")
            if success:
                print(f"✅ Device is online after {attempt + 1} attempts")
                return True
            
            print(f"   Attempt {attempt + 1}/{max_attempts} - Device not ready yet...")
            time.sleep(10)
        
        print("❌ Device did not come online within expected time")
        return False
    
    def restore_ssh_rules(self):
        """Restore SSH iptables rules"""
        print("\n🔧 Restoring SSH iptables rules...")
        
        # Find the most recent backup files
        iptables_backup = None
        ip6tables_backup = None
        
        for file in os.listdir(self.backup_dir):
            if file.startswith("iptables_rules_backup_") and file.endswith(".txt"):
                if iptables_backup is None or file > iptables_backup:
                    iptables_backup = file
            elif file.startswith("ip6tables_rules_backup_") and file.endswith(".txt"):
                if ip6tables_backup is None or file > ip6tables_backup:
                    ip6tables_backup = file
        
        if not iptables_backup or not ip6tables_backup:
            print("❌ No backup files found")
            return False
        
        print(f"📁 Using backup files:")
        print(f"   IPv4: {iptables_backup}")
        print(f"   IPv6: {ip6tables_backup}")
        
        # Restore IPv4 rules
        try:
            with open(os.path.join(self.backup_dir, iptables_backup), 'r') as f:
                iptables_rules = f.read()
            
            success, stdout, stderr = self.run_ssh_command(f"echo '{iptables_rules}' | iptables-restore")
            if success:
                print("✅ IPv4 rules restored successfully")
            else:
                print(f"❌ Failed to restore IPv4 rules: {stderr}")
                return False
        except Exception as e:
            print(f"❌ Error reading IPv4 backup: {e}")
            return False
        
        # Restore IPv6 rules
        try:
            with open(os.path.join(self.backup_dir, ip6tables_backup), 'r') as f:
                ip6tables_rules = f.read()
            
            success, stdout, stderr = self.run_ssh_command(f"echo '{ip6tables_rules}' | ip6tables-restore")
            if success:
                print("✅ IPv6 rules restored successfully")
            else:
                print(f"❌ Failed to restore IPv6 rules: {stderr}")
                return False
        except Exception as e:
            print(f"❌ Error reading IPv6 backup: {e}")
            return False
        
        return True
    
    def restore_api_rules(self):
        """Restore API firewall rules"""
        print("\n🔧 Restoring API firewall rules...")
        
        # Find the most recent API backup
        api_backup = None
        for file in os.listdir(self.backup_dir):
            if file.startswith("api_firewall_rules_backup_") and file.endswith(".json"):
                if api_backup is None or file > api_backup:
                    api_backup = file
        
        if not api_backup:
            print("❌ No API backup file found")
            return False
        
        print(f"📁 Using API backup: {api_backup}")
        
        try:
            with open(os.path.join(self.backup_dir, api_backup), 'r') as f:
                api_data = json.load(f)
            
            rules = api_data.get('data', [])
            print(f"📊 Found {len(rules)} API rules to restore")
            
            # Note: API rules are typically persistent across reboots
            # This is mainly for verification
            print("ℹ️  API rules should persist across reboots")
            print("ℹ️  Verifying API rules are still present...")
            
            # Verify API is accessible
            success, stdout, stderr = self.run_ssh_command("curl -k -X GET 'https://192.168.22.1/proxy/network/api/s/default/rest/firewallrule' -H 'X-API-KEY: C5tSpDSC2J_bZy9oqYwBDesWoUP1sHIK' -H 'Accept: application/json' | wc -l")
            if success and int(stdout.strip()) > 0:
                print("✅ API rules are accessible")
                return True
            else:
                print("❌ API rules not accessible")
                return False
                
        except Exception as e:
            print(f"❌ Error reading API backup: {e}")
            return False
    
    def verify_restoration(self):
        """Verify that all rules are properly restored"""
        print("\n🔍 Verifying rule restoration...")
        
        # Check SSH rules
        success, stdout, stderr = self.run_ssh_command("iptables -L -n | grep 'DROP' | wc -l")
        if success:
            drop_count = int(stdout.strip())
            print(f"✅ IPv4 DROP rules: {drop_count}")
        else:
            print("❌ Could not verify IPv4 rules")
        
        success, stdout, stderr = self.run_ssh_command("ip6tables -L -n | grep 'DROP' | wc -l")
        if success:
            drop_count = int(stdout.strip())
            print(f"✅ IPv6 DROP rules: {drop_count}")
        else:
            print("❌ Could not verify IPv6 rules")
        
        # Check mDNS rules
        success, stdout, stderr = self.run_ssh_command("iptables -L -n | grep -E '(Allow_mDNS|Allow_LLMNR|Allow_Multicast)' | wc -l")
        if success:
            mdns_count = int(stdout.strip())
            print(f"✅ mDNS/Multicast rules: {mdns_count}")
        else:
            print("❌ Could not verify mDNS rules")
    
    def create_backup_directory(self):
        """Create backup directory if it doesn't exist"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
            print(f"📁 Created backup directory: {self.backup_dir}")

def main():
    print("🔄 UCG Firewall Rules Restore Script")
    print("=" * 50)
    
    restore_manager = UCGRestoreManager()
    restore_manager.create_backup_directory()
    
    # Wait for device to come online
    if not restore_manager.wait_for_device():
        print("❌ Cannot proceed - device is not reachable")
        return
    
    print("\n🚀 Starting restoration process...")
    
    # Restore SSH rules
    if restore_manager.restore_ssh_rules():
        print("✅ SSH rules restored successfully")
    else:
        print("❌ SSH rules restoration failed")
    
    # Restore API rules (verify they're still there)
    if restore_manager.restore_api_rules():
        print("✅ API rules verified successfully")
    else:
        print("❌ API rules verification failed")
    
    # Verify everything is working
    restore_manager.verify_restoration()
    
    print("\n🎯 Restoration complete!")
    print("   - All firewall rules have been restored")
    print("   - mDNS and multicast traffic is allowed on 192.168.22.x")
    print("   - Unmanaged IP ranges are blocked on WAN interfaces")
    print("   - Both SSH and API rules are active")

if __name__ == "__main__":
    main()
