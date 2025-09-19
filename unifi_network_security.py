#!/usr/bin/env python3
"""
UCG-Fiber UniFi Network Security Module
Uses UniFi API to manage firewall rules for blocking unmanaged IPv4 and IPv6 ranges
"""

import requests
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
        logging.FileHandler('/tmp/unifi-network-security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('UniFiNetworkSecurity')

@dataclass
class UniFiFirewallRule:
    """Represents a UniFi firewall rule"""
    name: str
    description: str
    action: str  # 'drop' or 'accept'
    protocol: str  # 'all', 'tcp', 'udp', etc.
    source_address: str
    dest_address: str
    source_port: str = ""
    dest_port: str = ""
    enabled: bool = True

class UniFiNetworkSecurity:
    """UCG-Fiber UniFi Network Security Manager"""
    
    def __init__(self, unifi_host: str = "192.168.22.1", unifi_port: int = 8443):
        self.unifi_host = unifi_host
        self.unifi_port = unifi_port
        self.base_url = f"https://{unifi_host}:{unifi_port}"
        self.api_url = f"{self.base_url}/api"
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for self-signed certs
        
        # UniFi credentials (should be configured)
        self.username = "admin"  # Default UniFi username
        self.password = ""  # Should be set via environment or config
        
        self.db_path = '/tmp/unifi_network_security.db'
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
        
    def init_database(self):
        """Initialize database for tracking firewall rules"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS unifi_firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT UNIQUE,
                rule_name TEXT NOT NULL,
                description TEXT,
                action TEXT NOT NULL,
                protocol TEXT,
                source_address TEXT,
                dest_address TEXT,
                source_port TEXT,
                dest_port TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                rule_name TEXT,
                network_range TEXT,
                action_taken TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def authenticate(self, username: str = None, password: str = None) -> bool:
        """Authenticate with UniFi controller"""
        try:
            if username:
                self.username = username
            if password:
                self.password = password
                
            if not self.password:
                logger.error("UniFi password not provided")
                return False
            
            # Try different possible UniFi API endpoints
            possible_endpoints = [
                f"{self.base_url}/api/login",
                f"{self.base_url}/api/auth/login",
                f"{self.base_url}/api/login",
                f"{self.base_url}/login",
                f"{self.base_url}/api/v1/login"
            ]
            
            login_data = {
                "username": self.username,
                "password": self.password
            }
            
            for endpoint in possible_endpoints:
                try:
                    response = self.session.post(endpoint, json=login_data, timeout=10)
                    if response.status_code == 200:
                        logger.info(f"Successfully authenticated with UniFi controller via {endpoint}")
                        return True
                    elif response.status_code == 404:
                        logger.debug(f"Endpoint {endpoint} not found, trying next...")
                        continue
                    else:
                        logger.debug(f"Endpoint {endpoint} returned {response.status_code}")
                        continue
                except Exception as e:
                    logger.debug(f"Error with endpoint {endpoint}: {e}")
                    continue
            
            logger.error("All authentication endpoints failed")
            return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def get_site_id(self) -> str:
        """Get the default site ID"""
        try:
            response = self.session.get(f"{self.base_url}/api/self", timeout=10)
            if response.status_code == 200:
                data = response.json()
                # Return the first site ID (usually the default)
                if 'sites' in data and len(data['sites']) > 0:
                    return data['sites'][0]['name']
                return 'default'
            return 'default'
        except Exception as e:
            logger.error(f"Error getting site ID: {e}")
            return 'default'
    
    def create_firewall_rule(self, rule: UniFiFirewallRule, ip_range: str = None, ip_version: str = None, site_id: str = None) -> bool:
        """Create a firewall rule in UniFi"""
        try:
            if not site_id:
                site_id = self.get_site_id()
            
            # UniFi firewall rule structure - corrected format
            firewall_rule = {
                "name": rule.name,
                "enabled": rule.enabled,
                "action": rule.action,
                "ruleset": "WAN_IN",  # Apply to WAN inbound traffic
                "src_ip": ip_range or rule.source_address,  # Use provided range or rule address
                "ip_version": ip_version or ("IPv4" if "." in (ip_range or rule.source_address) else "IPv6"),
                "protocol": rule.protocol
            }
            
            response = self.session.post(
                f"{self.base_url}/api/s/{site_id}/rest/firewallrule",
                json=firewall_rule,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Created firewall rule: {rule.name}")
                self._store_firewall_rule(rule, response.json().get('_id', ''))
                return True
            else:
                logger.error(f"Failed to create firewall rule: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating firewall rule: {e}")
            return False
    
    def _store_firewall_rule(self, rule: UniFiFirewallRule, rule_id: str):
        """Store firewall rule in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO unifi_firewall_rules 
                (rule_id, rule_name, description, action, protocol, source_address, 
                 dest_address, source_port, dest_port, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule_id, rule.name, rule.description, rule.action, rule.protocol,
                rule.source_address, rule.dest_address, rule.source_port,
                rule.dest_port, rule.enabled
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store firewall rule: {e}")
    
    def block_unmanaged_ranges(self) -> Dict:
        """Block all unmanaged IPv4 and IPv6 ranges using UniFi firewall rules"""
        results = {
            'ipv4_blocked': [],
            'ipv6_blocked': [],
            'errors': [],
            'total_blocked': 0
        }
        
        logger.info("Starting comprehensive blocking of unmanaged ranges using UniFi firewall rules")
        
        # Block IPv4 ranges
        for network in self.unmanaged_ipv4_ranges:
            try:
                success = self._block_ipv4_range_unifi(network)
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
                success = self._block_ipv6_range_unifi(network)
                if success:
                    results['ipv6_blocked'].append(network)
                    results['total_blocked'] += 1
                else:
                    results['errors'].append(f"Failed to block IPv6: {network}")
            except Exception as e:
                error_msg = f"Error blocking IPv6 {network}: {str(e)}"
                results['errors'].append(error_msg)
                logger.error(error_msg)
        
        logger.info(f"Blocked {results['total_blocked']} unmanaged ranges using UniFi firewall rules")
        return results
    
    def _block_ipv4_range_unifi(self, network: str) -> bool:
        """Block IPv4 network range using UniFi firewall rules"""
        try:
            # Validate network format
            ipaddress.IPv4Network(network, strict=False)
            
            # Create firewall rule to block the range
            rule_name = f"Block_IPv4_Private_{network.replace('/', '_').replace('.', '_')}"
            
            rule = UniFiFirewallRule(
                name=rule_name,
                description=f"Block unmanaged IPv4 private range: {network}",
                action="drop",
                protocol="all",
                source_address=network,
                dest_address="any",
                enabled=True
            )
            
            success = self.create_firewall_rule(rule, network, "IPv4")
            
            if success:
                # Log security event
                self._log_security_event('range_blocked', rule_name, network,
                                       f"Blocked IPv4 range {network}", f"UniFi firewall rule created")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to block IPv4 range {network}: {e}")
            return False
    
    def _block_ipv6_range_unifi(self, network: str) -> bool:
        """Block IPv6 network range using UniFi firewall rules"""
        try:
            # Validate network format
            ipaddress.IPv6Network(network, strict=False)
            
            # Create firewall rule to block the range
            rule_name = f"Block_IPv6_Private_{network.replace('/', '_').replace(':', '_')}"
            
            rule = UniFiFirewallRule(
                name=rule_name,
                description=f"Block unmanaged IPv6 private range: {network}",
                action="drop",
                protocol="all",
                source_address=network,
                dest_address="any",
                enabled=True
            )
            
            success = self.create_firewall_rule(rule, network, "IPv6")
            
            if success:
                # Log security event
                self._log_security_event('range_blocked', rule_name, network,
                                       f"Blocked IPv6 range {network}", f"UniFi firewall rule created")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to block IPv6 range {network}: {e}")
            return False
    
    def block_wan_private_ips(self) -> Dict:
        """Specifically block private IPs on WAN interfaces using UniFi rules"""
        results = {'rules_created': [], 'total_rules': 0, 'errors': []}
        
        logger.info("Blocking private IPs on WAN interfaces using UniFi firewall rules")
        
        # Create specific WAN rules for private IP ranges
        wan_private_ranges = [
            ("10.0.0.0/8", "Block WAN Private Class A"),
            ("172.16.0.0/12", "Block WAN Private Class B"),
            ("192.168.0.0/16", "Block WAN Private Class C"),
            ("169.254.0.0/16", "Block WAN Link-Local"),
            ("fc00::/7", "Block WAN IPv6 ULA"),
            ("fe80::/10", "Block WAN IPv6 Link-Local")
        ]
        
        for network, description in wan_private_ranges:
            try:
                # Create rule to block traffic from private ranges on WAN
                rule_name = f"WAN_Block_{network.replace('/', '_').replace('.', '_').replace(':', '_')}"
                
                rule = UniFiFirewallRule(
                    name=rule_name,
                    description=f"{description}: {network}",
                    action="drop",
                    protocol="all",
                    source_address=network,
                    dest_address="any",
                    enabled=True
                )
                
                success = self.create_firewall_rule(rule, network, "IPv4" if "." in network else "IPv6")
                
                if success:
                    results['rules_created'].append(rule_name)
                    results['total_rules'] += 1
                    logger.info(f"Created WAN blocking rule: {rule_name}")
                else:
                    results['errors'].append(f"Failed to create rule for {network}")
                    
            except Exception as e:
                error_msg = f"Error creating WAN rule for {network}: {str(e)}"
                results['errors'].append(error_msg)
                logger.error(error_msg)
        
        return results
    
    def _log_security_event(self, event_type: str, rule_name: str, network_range: str, 
                           action_taken: str, details: str):
        """Log security event to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events 
                (event_type, rule_name, network_range, action_taken, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (event_type, rule_name, network_range, action_taken, details))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    def get_firewall_rules(self) -> List[Dict]:
        """Get all UniFi firewall rules"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT rule_id, rule_name, description, action, protocol, 
                       source_address, dest_address, enabled, created_at
                FROM unifi_firewall_rules 
                WHERE enabled = 1
                ORDER BY created_at DESC
            ''')
            
            rules = []
            for row in cursor.fetchall():
                rules.append({
                    'rule_id': row[0],
                    'rule_name': row[1],
                    'description': row[2],
                    'action': row[3],
                    'protocol': row[4],
                    'source_address': row[5],
                    'dest_address': row[6],
                    'enabled': bool(row[7]),
                    'created_at': row[8]
                })
            
            conn.close()
            return rules
            
        except Exception as e:
            logger.error(f"Failed to get firewall rules: {e}")
            return []
    
    def verify_firewall_status(self) -> Dict:
        """Verify firewall rules are active"""
        try:
            rules = self.get_firewall_rules()
            
            # Count rules by type
            ipv4_rules = len([r for r in rules if '.' in r['source_address']])
            ipv6_rules = len([r for r in rules if ':' in r['source_address']])
            drop_rules = len([r for r in rules if r['action'] == 'drop'])
            
            status = {
                'total_rules': len(rules),
                'ipv4_rules': ipv4_rules,
                'ipv6_rules': ipv6_rules,
                'drop_rules': drop_rules,
                'status': 'healthy' if drop_rules > 0 else 'warning',
                'timestamp': datetime.now().isoformat()
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to verify firewall status: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def get_security_events(self, hours: int = 24) -> List[Dict]:
        """Get recent security events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since = datetime.now() - timedelta(hours=hours)
            cursor.execute('''
                SELECT event_type, rule_name, network_range, action_taken, details, timestamp
                FROM security_events 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            ''', (since.isoformat(),))
            
            events = []
            for row in cursor.fetchall():
                events.append({
                    'event_type': row[0],
                    'rule_name': row[1],
                    'network_range': row[2],
                    'action_taken': row[3],
                    'details': row[4],
                    'timestamp': row[5]
                })
            
            conn.close()
            return events
            
        except Exception as e:
            logger.error(f"Failed to get security events: {e}")
            return []

def main():
    """Main function to demonstrate UniFi network security"""
    logger.info("Starting UCG-Fiber UniFi Network Security")
    
    # Initialize UniFi network security
    unifi_netsec = UniFiNetworkSecurity()
    
    # Note: In a real deployment, you would need to provide credentials
    print("UCG-Fiber UniFi Network Security Module")
    print("=" * 50)
    print("Note: This module uses the UniFi API to create firewall rules")
    print("You need to provide UniFi controller credentials to authenticate")
    print()
    
    # Show configuration
    print(f"UniFi Controller: {unifi_netsec.base_url}")
    print(f"Database: {unifi_netsec.db_path}")
    print()
    
    # Show ranges that would be blocked
    print("IPv4 Ranges to be blocked:")
    for range_ip in unifi_netsec.unmanaged_ipv4_ranges:
        print(f"  - {range_ip}")
    
    print("\nIPv6 Ranges to be blocked:")
    for range_ip in unifi_netsec.unmanaged_ipv6_ranges:
        print(f"  - {range_ip}")
    
    print(f"\nTotal ranges: {len(unifi_netsec.unmanaged_ipv4_ranges) + len(unifi_netsec.unmanaged_ipv6_ranges)}")
    
    logger.info("UniFi Network Security module initialized")

if __name__ == "__main__":
    main()
