#!/usr/bin/env python3
"""
UCG-Fiber Network Security Module
Comprehensive blocking of unmanaged IPv4 and IPv6 ranges, especially WAN interfaces with private IPs
"""

import subprocess
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple
import ipaddress
import threading
import time
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/network-security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NetworkSecurity')

@dataclass
class NetworkRange:
    """Represents a network range to be blocked"""
    network: str
    protocol: str  # 'ipv4' or 'ipv6'
    interface: str
    reason: str
    priority: int = 100

class UCGNetworkSecurity:
    """UCG-Fiber Network Security Manager for blocking unmanaged ranges"""
    
    def __init__(self, ucg_ip: str = "192.168.22.1", ssh_key_path: str = "~/.ssh/ucg_fiber_key"):
        self.ucg_ip = ucg_ip
        self.ssh_key_path = ssh_key_path
        self.db_path = '/tmp/network_security.db'
        self.blocked_ranges = set()
        self.active_rules = {}
        
        # Define unmanaged IP ranges that must be blocked
        self.unmanaged_ipv4_ranges = [
            # RFC 1918 Private Address Ranges
            "10.0.0.0/8",           # Class A private
            "172.16.0.0/12",        # Class B private
            "192.168.0.0/16",       # Class C private
            
            # RFC 3927 Link-Local addresses
            "169.254.0.0/16",       # Link-local
            
            # RFC 1918 Reserved ranges
            "127.0.0.0/8",          # Loopback
            "0.0.0.0/8",            # Current network
            "224.0.0.0/4",          # Multicast
            "240.0.0.0/4",          # Reserved
            
            # Additional problematic ranges
            "192.0.2.0/24",         # Test-NET-1
            "198.51.100.0/24",      # Test-NET-2
            "203.0.113.0/24",       # Test-NET-3
            "198.18.0.0/15",        # Benchmarking
        ]
        
        self.unmanaged_ipv6_ranges = [
            # RFC 4193 Unique Local Addresses
            "fc00::/7",             # ULA
            
            # RFC 4291 Link-Local addresses
            "fe80::/10",            # Link-local
            
            # RFC 4291 Loopback
            "::1/128",              # Loopback
            
            # RFC 4291 Multicast
            "ff00::/8",             # Multicast
            
            # RFC 4291 Documentation
            "2001:db8::/32",        # Documentation
            
            # RFC 4291 Reserved
            "::/128",               # Unspecified
            "::ffff:0:0/96",        # IPv4-mapped
            "64:ff9b::/96",         # IPv4-IPv6 translation
        ]
        
        self.init_database()
        self.load_existing_rules()
        
    def init_database(self):
        """Initialize database for tracking blocked ranges"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ranges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT NOT NULL,
                protocol TEXT NOT NULL,
                interface TEXT NOT NULL,
                reason TEXT,
                priority INTEGER DEFAULT 100,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                status TEXT DEFAULT 'active',
                UNIQUE(network, interface)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                network_range TEXT,
                interface TEXT,
                action_taken TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def load_existing_rules(self):
        """Load existing firewall rules from UCG-Fiber device"""
        try:
            # Get current iptables rules
            ssh_command = [
                'ssh', '-i', self.ssh_key_path, '-o', 'StrictHostKeyChecking=no',
                f'root@{self.ucg_ip}',
                'iptables -L -n --line-numbers | grep "DROP"'
            ]
            
            result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and 'DROP' in line:
                        logger.info(f"Existing DROP rule found: {line}")
                        
            # Get IPv6 rules
            ssh_command_ipv6 = [
                'ssh', '-i', self.ssh_key_path, '-o', 'StrictHostKeyChecking=no',
                f'root@{self.ucg_ip}',
                'ip6tables -L -n --line-numbers | grep "DROP"'
            ]
            
            result_ipv6 = subprocess.run(ssh_command_ipv6, capture_output=True, text=True, timeout=15)
            
            if result_ipv6.returncode == 0:
                for line in result_ipv6.stdout.strip().split('\n'):
                    if line and 'DROP' in line:
                        logger.info(f"Existing IPv6 DROP rule found: {line}")
                        
        except Exception as e:
            logger.error(f"Failed to load existing rules: {e}")
    
    def block_unmanaged_ranges(self, interface: str = "wan") -> Dict:
        """Block all unmanaged IPv4 and IPv6 ranges on specified interface"""
        results = {
            'ipv4_blocked': [],
            'ipv6_blocked': [],
            'errors': [],
            'total_blocked': 0
        }
        
        logger.info(f"Starting comprehensive blocking of unmanaged ranges on {interface} interface")
        
        # Block IPv4 ranges
        for network in self.unmanaged_ipv4_ranges:
            try:
                success = self._block_ipv4_range(network, interface, f"Unmanaged private range: {network}")
                if success:
                    results['ipv4_blocked'].append(network)
                    results['total_blocked'] += 1
                else:
                    results['errors'].append(f"Failed to block IPv4: {network}")
            except Exception as e:
                error_msg = f"Error blocking IPv4 {network}: {str(e)}"
                results['errors'].append(error_msg)
                logger.error(error_msg)
        
        # Block IPv6 ranges
        for network in self.unmanaged_ipv6_ranges:
            try:
                success = self._block_ipv6_range(network, interface, f"Unmanaged private range: {network}")
                if success:
                    results['ipv6_blocked'].append(network)
                    results['total_blocked'] += 1
                else:
                    results['errors'].append(f"Failed to block IPv6: {network}")
            except Exception as e:
                error_msg = f"Error blocking IPv6 {network}: {str(e)}"
                results['errors'].append(error_msg)
                logger.error(error_msg)
        
        logger.info(f"Blocked {results['total_blocked']} unmanaged ranges on {interface} interface")
        return results
    
    def _block_ipv4_range(self, network: str, interface: str, reason: str) -> bool:
        """Block IPv4 network range using UCG-Fiber API via SSH"""
        try:
            # Validate network format
            ipaddress.IPv4Network(network, strict=False)
            
            # Create iptables rules to block the range
            rules = [
                f"iptables -I FORWARD -i {interface} -s {network} -j DROP",
                f"iptables -I FORWARD -o {interface} -d {network} -j DROP",
                f"iptables -I INPUT -i {interface} -s {network} -j DROP",
                f"iptables -I OUTPUT -o {interface} -d {network} -j DROP"
            ]
            
            for rule in rules:
                ssh_command = [
                    'ssh', '-i', self.ssh_key_path, '-o', 'StrictHostKeyChecking=no',
                    f'root@{self.ucg_ip}',
                    rule
                ]
                
                result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    logger.warning(f"Rule may already exist: {rule}")
                else:
                    logger.info(f"Applied IPv4 rule: {rule}")
            
            # Store in database
            self._store_blocked_range(network, 'ipv4', interface, reason)
            
            # Log security event
            self._log_security_event('range_blocked', None, network, interface, 
                                   f"Blocked IPv4 range {network}", f"Reason: {reason}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IPv4 range {network}: {e}")
            return False
    
    def _block_ipv6_range(self, network: str, interface: str, reason: str) -> bool:
        """Block IPv6 network range using UCG-Fiber API via SSH"""
        try:
            # Validate network format
            ipaddress.IPv6Network(network, strict=False)
            
            # Create ip6tables rules to block the range
            rules = [
                f"ip6tables -I FORWARD -i {interface} -s {network} -j DROP",
                f"ip6tables -I FORWARD -o {interface} -d {network} -j DROP",
                f"ip6tables -I INPUT -i {interface} -s {network} -j DROP",
                f"ip6tables -I OUTPUT -o {interface} -d {network} -j DROP"
            ]
            
            for rule in rules:
                ssh_command = [
                    'ssh', '-i', self.ssh_key_path, '-o', 'StrictHostKeyChecking=no',
                    f'root@{self.ucg_ip}',
                    rule
                ]
                
                result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    logger.warning(f"IPv6 rule may already exist: {rule}")
                else:
                    logger.info(f"Applied IPv6 rule: {rule}")
            
            # Store in database
            self._store_blocked_range(network, 'ipv6', interface, reason)
            
            # Log security event
            self._log_security_event('range_blocked', None, network, interface,
                                   f"Blocked IPv6 range {network}", f"Reason: {reason}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IPv6 range {network}: {e}")
            return False
    
    def _store_blocked_range(self, network: str, protocol: str, interface: str, reason: str):
        """Store blocked range in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ranges 
                (network, protocol, interface, reason, status)
                VALUES (?, ?, ?, ?, 'active')
            ''', (network, protocol, interface, reason))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store blocked range: {e}")
    
    def _log_security_event(self, event_type: str, source_ip: str, network_range: str, 
                           interface: str, action_taken: str, details: str):
        """Log security event to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events 
                (event_type, source_ip, network_range, interface, action_taken, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (event_type, source_ip, network_range, interface, action_taken, details))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    def block_wan_private_ips(self) -> Dict:
        """Specifically block private IPs on WAN interfaces"""
        wan_interfaces = ['wan', 'wan1', 'wan2', 'ppp0', 'eth0', 'eth1']
        results = {'interfaces_processed': [], 'total_rules_applied': 0, 'errors': []}
        
        logger.info("Blocking private IPs on all WAN interfaces")
        
        for interface in wan_interfaces:
            try:
                # Block private IPv4 ranges on WAN
                private_ranges = [
                    "10.0.0.0/8",
                    "172.16.0.0/12", 
                    "192.168.0.0/16",
                    "169.254.0.0/16"
                ]
                
                for network in private_ranges:
                    success = self._block_ipv4_range(network, interface, 
                                                   f"Private IP on WAN interface {interface}")
                    if success:
                        results['total_rules_applied'] += 1
                
                # Block IPv6 ULA and link-local on WAN
                ipv6_ranges = ["fc00::/7", "fe80::/10"]
                for network in ipv6_ranges:
                    success = self._block_ipv6_range(network, interface,
                                                   f"Private IPv6 on WAN interface {interface}")
                    if success:
                        results['total_rules_applied'] += 1
                
                results['interfaces_processed'].append(interface)
                logger.info(f"Processed WAN interface: {interface}")
                
            except Exception as e:
                error_msg = f"Error processing WAN interface {interface}: {str(e)}"
                results['errors'].append(error_msg)
                logger.error(error_msg)
        
        return results
    
    def get_blocked_ranges(self) -> List[Dict]:
        """Get list of currently blocked ranges"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT network, protocol, interface, reason, created_at, status
                FROM blocked_ranges 
                WHERE status = 'active'
                ORDER BY created_at DESC
            ''')
            
            ranges = []
            for row in cursor.fetchall():
                ranges.append({
                    'network': row[0],
                    'protocol': row[1],
                    'interface': row[2],
                    'reason': row[3],
                    'created_at': row[4],
                    'status': row[5]
                })
            
            conn.close()
            return ranges
            
        except Exception as e:
            logger.error(f"Failed to get blocked ranges: {e}")
            return []
    
    def get_security_events(self, hours: int = 24) -> List[Dict]:
        """Get recent security events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since = datetime.now() - timedelta(hours=hours)
            cursor.execute('''
                SELECT event_type, source_ip, network_range, interface, 
                       action_taken, details, timestamp
                FROM security_events 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            ''', (since.isoformat(),))
            
            events = []
            for row in cursor.fetchall():
                events.append({
                    'event_type': row[0],
                    'source_ip': row[1],
                    'network_range': row[2],
                    'interface': row[3],
                    'action_taken': row[4],
                    'details': row[5],
                    'timestamp': row[6]
                })
            
            conn.close()
            return events
            
        except Exception as e:
            logger.error(f"Failed to get security events: {e}")
            return []
    
    def verify_blocking_status(self) -> Dict:
        """Verify that all unmanaged ranges are properly blocked"""
        try:
            # Check IPv4 rules
            ssh_command = [
                'ssh', '-i', self.ssh_key_path, '-o', 'StrictHostKeyChecking=no',
                f'root@{self.ucg_ip}',
                'iptables -L -n | grep "DROP" | wc -l'
            ]
            
            result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=10)
            ipv4_rules = int(result.stdout.strip()) if result.returncode == 0 else 0
            
            # Check IPv6 rules
            ssh_command_ipv6 = [
                'ssh', '-i', self.ssh_key_path, '-o', 'StrictHostKeyChecking=no',
                f'root@{self.ucg_ip}',
                'ip6tables -L -n | grep "DROP" | wc -l'
            ]
            
            result_ipv6 = subprocess.run(ssh_command_ipv6, capture_output=True, text=True, timeout=10)
            ipv6_rules = int(result_ipv6.stdout.strip()) if result_ipv6.returncode == 0 else 0
            
            # Get database counts
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM blocked_ranges WHERE status = "active"')
            db_rules = cursor.fetchone()[0]
            conn.close()
            
            return {
                'ipv4_firewall_rules': ipv4_rules,
                'ipv6_firewall_rules': ipv6_rules,
                'database_rules': db_rules,
                'status': 'healthy' if ipv4_rules > 0 and ipv6_rules > 0 else 'warning',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to verify blocking status: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def cleanup_expired_rules(self):
        """Clean up expired blocking rules"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Find expired rules
            now = datetime.now()
            cursor.execute('''
                SELECT network, protocol, interface 
                FROM blocked_ranges 
                WHERE expires_at IS NOT NULL AND expires_at < ?
            ''', (now.isoformat(),))
            
            expired_rules = cursor.fetchall()
            
            for network, protocol, interface in expired_rules:
                # Remove from firewall
                if protocol == 'ipv4':
                    self._remove_ipv4_rule(network, interface)
                else:
                    self._remove_ipv6_rule(network, interface)
                
                # Mark as expired in database
                cursor.execute('''
                    UPDATE blocked_ranges 
                    SET status = 'expired' 
                    WHERE network = ? AND interface = ?
                ''', (network, interface))
                
                logger.info(f"Cleaned up expired rule: {network} on {interface}")
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired rules: {e}")
    
    def _remove_ipv4_rule(self, network: str, interface: str):
        """Remove IPv4 blocking rule"""
        try:
            rules_to_remove = [
                f"iptables -D FORWARD -i {interface} -s {network} -j DROP",
                f"iptables -D FORWARD -o {interface} -d {network} -j DROP",
                f"iptables -D INPUT -i {interface} -s {network} -j DROP",
                f"iptables -D OUTPUT -o {interface} -d {network} -j DROP"
            ]
            
            for rule in rules_to_remove:
                ssh_command = [
                    'ssh', '-i', self.ssh_key_path, '-o', 'StrictHostKeyChecking=no',
                    f'root@{self.ucg_ip}',
                    rule
                ]
                subprocess.run(ssh_command, capture_output=True, text=True, timeout=10)
                
        except Exception as e:
            logger.error(f"Failed to remove IPv4 rule for {network}: {e}")
    
    def _remove_ipv6_rule(self, network: str, interface: str):
        """Remove IPv6 blocking rule"""
        try:
            rules_to_remove = [
                f"ip6tables -D FORWARD -i {interface} -s {network} -j DROP",
                f"ip6tables -D FORWARD -o {interface} -d {network} -j DROP",
                f"ip6tables -D INPUT -i {interface} -s {network} -j DROP",
                f"ip6tables -D OUTPUT -o {interface} -d {network} -j DROP"
            ]
            
            for rule in rules_to_remove:
                ssh_command = [
                    'ssh', '-i', self.ssh_key_path, '-o', 'StrictHostKeyChecking=no',
                    f'root@{self.ucg_ip}',
                    rule
                ]
                subprocess.run(ssh_command, capture_output=True, text=True, timeout=10)
                
        except Exception as e:
            logger.error(f"Failed to remove IPv6 rule for {network}: {e}")

def main():
    """Main function to demonstrate comprehensive network blocking"""
    logger.info("Starting UCG-Fiber Network Security - Comprehensive Range Blocking")
    
    # Initialize network security
    netsec = UCGNetworkSecurity()
    
    # Block all unmanaged ranges
    logger.info("=== Blocking All Unmanaged IPv4 and IPv6 Ranges ===")
    results = netsec.block_unmanaged_ranges()
    
    print(f"\n=== Blocking Results ===")
    print(f"IPv4 ranges blocked: {len(results['ipv4_blocked'])}")
    print(f"IPv6 ranges blocked: {len(results['ipv6_blocked'])}")
    print(f"Total ranges blocked: {results['total_blocked']}")
    
    if results['errors']:
        print(f"Errors: {len(results['errors'])}")
        for error in results['errors']:
            print(f"  - {error}")
    
    # Specifically block private IPs on WAN interfaces
    logger.info("=== Blocking Private IPs on WAN Interfaces ===")
    wan_results = netsec.block_wan_private_ips()
    
    print(f"\n=== WAN Interface Blocking Results ===")
    print(f"Interfaces processed: {len(wan_results['interfaces_processed'])}")
    print(f"Total rules applied: {wan_results['total_rules_applied']}")
    
    # Verify blocking status
    logger.info("=== Verifying Blocking Status ===")
    status = netsec.verify_blocking_status()
    
    print(f"\n=== Blocking Status ===")
    print(f"IPv4 firewall rules: {status.get('ipv4_firewall_rules', 0)}")
    print(f"IPv6 firewall rules: {status.get('ipv6_firewall_rules', 0)}")
    print(f"Database rules: {status.get('database_rules', 0)}")
    print(f"Status: {status.get('status', 'unknown')}")
    
    # Show blocked ranges
    blocked_ranges = netsec.get_blocked_ranges()
    print(f"\n=== Currently Blocked Ranges ({len(blocked_ranges)}) ===")
    for range_info in blocked_ranges[:10]:  # Show first 10
        print(f"{range_info['protocol'].upper()}: {range_info['network']} on {range_info['interface']} - {range_info['reason']}")
    
    if len(blocked_ranges) > 10:
        print(f"... and {len(blocked_ranges) - 10} more ranges")
    
    logger.info("UCG-Fiber Network Security initialization complete")

if __name__ == "__main__":
    main()
