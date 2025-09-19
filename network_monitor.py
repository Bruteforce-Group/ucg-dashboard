#!/usr/bin/env python3
"""
UCG-Fiber Network Security Monitor
Automated monitoring and enforcement of network security policies
"""

import time
import threading
import logging
from datetime import datetime, timedelta
from network_security import UCGNetworkSecurity
import requests
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/network-monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NetworkMonitor')

class NetworkSecurityMonitor:
    """Continuous monitoring and enforcement of network security policies"""
    
    def __init__(self, ucg_ip: str = "192.168.22.1", api_endpoint: str = "http://localhost:5000"):
        self.ucg_ip = ucg_ip
        self.api_endpoint = api_endpoint
        self.network_security = UCGNetworkSecurity(ucg_ip, "~/.ssh/ucg_fiber_key")
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Monitoring configuration
        self.check_interval = 300  # 5 minutes
        self.alert_threshold = 10  # Alert if more than 10 blocked ranges change
        
        # Statistics
        self.stats = {
            'checks_performed': 0,
            'ranges_blocked': 0,
            'alerts_generated': 0,
            'last_check': None,
            'uptime_start': datetime.now()
        }
        
    def start_monitoring(self):
        """Start continuous network security monitoring"""
        if self.monitoring_active:
            logger.warning("Monitoring is already active")
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Network security monitoring started")
        
        # Perform initial comprehensive blocking
        self._ensure_comprehensive_blocking()
    
    def stop_monitoring(self):
        """Stop network security monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("Network security monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._perform_security_check()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def _perform_security_check(self):
        """Perform comprehensive security check"""
        logger.info("Performing network security check...")
        
        try:
            # Verify current blocking status
            status = self.network_security.verify_blocking_status()
            
            # Check if blocking is sufficient
            if status.get('status') != 'healthy':
                logger.warning("Network blocking status is not healthy, enforcing policies...")
                self._ensure_comprehensive_blocking()
            
            # Clean up expired rules
            self.network_security.cleanup_expired_rules()
            
            # Update statistics
            self.stats['checks_performed'] += 1
            self.stats['last_check'] = datetime.now()
            
            # Check for security events
            recent_events = self.network_security.get_security_events(1)  # Last hour
            if len(recent_events) > self.alert_threshold:
                self._generate_alert(f"High number of security events: {len(recent_events)} in the last hour")
            
            logger.info(f"Security check completed. Status: {status.get('status', 'unknown')}")
            
        except Exception as e:
            logger.error(f"Error during security check: {e}")
            self._generate_alert(f"Security check failed: {str(e)}")
    
    def _ensure_comprehensive_blocking(self):
        """Ensure all unmanaged ranges are comprehensively blocked"""
        logger.info("Enforcing comprehensive network blocking...")
        
        try:
            # Block all unmanaged ranges
            unmanaged_results = self.network_security.block_unmanaged_ranges()
            
            # Block private IPs on WAN interfaces
            wan_results = self.network_security.block_wan_private_ips()
            
            total_actions = unmanaged_results['total_blocked'] + wan_results['total_rules_applied']
            
            if total_actions > 0:
                logger.info(f"Comprehensive blocking applied: {total_actions} total actions")
                self.stats['ranges_blocked'] += total_actions
                
                # Verify the blocking worked
                status = self.network_security.verify_blocking_status()
                if status.get('status') == 'healthy':
                    logger.info("Network security policies successfully enforced")
                else:
                    self._generate_alert("Failed to properly enforce network security policies")
            
        except Exception as e:
            logger.error(f"Error during comprehensive blocking: {e}")
            self._generate_alert(f"Comprehensive blocking failed: {str(e)}")
    
    def _generate_alert(self, message: str):
        """Generate security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': 'warning',
            'message': message,
            'source': 'network_monitor'
        }
        
        logger.warning(f"SECURITY ALERT: {message}")
        self.stats['alerts_generated'] += 1
        
        # Store alert in database
        self.network_security._log_security_event(
            'monitor_alert', None, None, 'all',
            f"Alert generated: {message}", alert
        )
        
        # Optionally send to external monitoring system
        try:
            self._send_to_api(alert)
        except Exception as e:
            logger.error(f"Failed to send alert to API: {e}")
    
    def _send_to_api(self, data: dict):
        """Send data to the API server"""
        try:
            response = requests.post(
                f"{self.api_endpoint}/api/network-security/alert",
                json=data,
                timeout=10
            )
            if response.status_code != 200:
                logger.warning(f"API returned status {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to send data to API: {e}")
    
    def get_monitoring_status(self) -> dict:
        """Get current monitoring status and statistics"""
        uptime = datetime.now() - self.stats['uptime_start']
        
        return {
            'monitoring_active': self.monitoring_active,
            'ucg_ip': self.ucg_ip,
            'api_endpoint': self.api_endpoint,
            'check_interval_seconds': self.check_interval,
            'statistics': {
                **self.stats,
                'uptime_seconds': int(uptime.total_seconds()),
                'uptime_human': str(uptime).split('.')[0]  # Remove microseconds
            },
            'last_check': self.stats['last_check'].isoformat() if self.stats['last_check'] else None
        }
    
    def force_comprehensive_block(self) -> dict:
        """Force immediate comprehensive blocking of all unmanaged ranges"""
        logger.info("Forcing immediate comprehensive network blocking...")
        
        try:
            # Block all unmanaged ranges
            unmanaged_results = self.network_security.block_unmanaged_ranges()
            
            # Block private IPs on WAN interfaces  
            wan_results = self.network_security.block_wan_private_ips()
            
            # Verify status
            status = self.network_security.verify_blocking_status()
            
            result = {
                'unmanaged_blocking': unmanaged_results,
                'wan_private_blocking': wan_results,
                'verification_status': status,
                'total_actions': unmanaged_results['total_blocked'] + wan_results['total_rules_applied'],
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"Comprehensive blocking completed: {result['total_actions']} total actions")
            
            # Update statistics
            self.stats['ranges_blocked'] += result['total_actions']
            
            return result
            
        except Exception as e:
            logger.error(f"Error during forced comprehensive blocking: {e}")
            raise
    
    def get_security_summary(self) -> dict:
        """Get comprehensive security summary"""
        try:
            # Get blocked ranges
            blocked_ranges = self.network_security.get_blocked_ranges()
            
            # Get recent security events
            recent_events = self.network_security.get_security_events(24)  # Last 24 hours
            
            # Get verification status
            status = self.network_security.verify_blocking_status()
            
            # Calculate statistics
            ipv4_count = len([r for r in blocked_ranges if r['protocol'] == 'ipv4'])
            ipv6_count = len([r for r in blocked_ranges if r['protocol'] == 'ipv6'])
            
            return {
                'blocked_ranges': {
                    'total': len(blocked_ranges),
                    'ipv4': ipv4_count,
                    'ipv6': ipv6_count,
                    'ranges': blocked_ranges[:20]  # First 20 ranges
                },
                'security_events': {
                    'total_last_24h': len(recent_events),
                    'recent_events': recent_events[:10]  # First 10 events
                },
                'verification_status': status,
                'monitoring_status': self.get_monitoring_status(),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting security summary: {e}")
            return {'error': str(e)}

def main():
    """Main function for network security monitoring"""
    logger.info("Starting UCG-Fiber Network Security Monitor")
    
    # Initialize monitor
    monitor = NetworkSecurityMonitor()
    
    try:
        # Start monitoring
        monitor.start_monitoring()
        
        # Perform initial comprehensive blocking
        logger.info("Performing initial comprehensive network blocking...")
        result = monitor.force_comprehensive_block()
        
        print("\n=== Initial Comprehensive Blocking Results ===")
        print(f"IPv4 ranges blocked: {len(result['unmanaged_blocking']['ipv4_blocked'])}")
        print(f"IPv6 ranges blocked: {len(result['unmanaged_blocking']['ipv6_blocked'])}")
        print(f"Total actions: {result['total_actions']}")
        print(f"Status: {result['verification_status'].get('status', 'unknown')}")
        
        if result['unmanaged_blocking']['errors']:
            print(f"Errors: {len(result['unmanaged_blocking']['errors'])}")
            for error in result['unmanaged_blocking']['errors'][:5]:
                print(f"  - {error}")
        
        # Show monitoring status
        status = monitor.get_monitoring_status()
        print(f"\n=== Monitoring Status ===")
        print(f"Monitoring active: {status['monitoring_active']}")
        print(f"Check interval: {status['check_interval_seconds']} seconds")
        print(f"UCG IP: {status['ucg_ip']}")
        
        # Get security summary
        summary = monitor.get_security_summary()
        print(f"\n=== Security Summary ===")
        print(f"Total blocked ranges: {summary['blocked_ranges']['total']}")
        print(f"IPv4 blocked: {summary['blocked_ranges']['ipv4']}")
        print(f"IPv6 blocked: {summary['blocked_ranges']['ipv6']}")
        print(f"Security events (24h): {summary['security_events']['total_last_24h']}")
        
        # Keep running
        logger.info("Network security monitor is now running. Press Ctrl+C to stop.")
        
        while True:
            time.sleep(60)
            
            # Show periodic status
            if monitor.stats['checks_performed'] % 12 == 0:  # Every hour
                logger.info(f"Monitor running for {status['statistics']['uptime_human']}")
                logger.info(f"Checks performed: {monitor.stats['checks_performed']}")
                logger.info(f"Total ranges blocked: {monitor.stats['ranges_blocked']}")
    
    except KeyboardInterrupt:
        logger.info("Shutting down network security monitor...")
        monitor.stop_monitoring()
        logger.info("Monitor stopped")
    
    except Exception as e:
        logger.error(f"Monitor error: {e}")
        monitor.stop_monitoring()
        raise

if __name__ == "__main__":
    main()
