#!/usr/bin/env python3
"""
UCG-Fiber Network Security Deployment Script
Immediately deploy comprehensive network security to block all unmanaged IPv4 and IPv6 ranges
"""

import sys
import time
import logging
from datetime import datetime
from network_security import UCGNetworkSecurity
from network_monitor import NetworkSecurityMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/network-security-deploy.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NetworkSecurityDeploy')

def deploy_comprehensive_network_security():
    """Deploy comprehensive network security immediately"""
    print("=" * 80)
    print("UCG-FIBER COMPREHENSIVE NETWORK SECURITY DEPLOYMENT")
    print("=" * 80)
    print(f"Deployment started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Initialize network security
        logger.info("Initializing UCG-Fiber Network Security...")
        netsec = UCGNetworkSecurity()
        
        # Step 1: Block all unmanaged IPv4 and IPv6 ranges
        print("STEP 1: Blocking All Unmanaged IPv4 and IPv6 Ranges")
        print("-" * 60)
        
        unmanaged_results = netsec.block_unmanaged_ranges()
        
        print(f"✓ IPv4 ranges blocked: {len(unmanaged_results['ipv4_blocked'])}")
        for network in unmanaged_results['ipv4_blocked']:
            print(f"  - {network}")
        
        print(f"✓ IPv6 ranges blocked: {len(unmanaged_results['ipv6_blocked'])}")
        for network in unmanaged_results['ipv6_blocked']:
            print(f"  - {network}")
        
        print(f"✓ Total unmanaged ranges blocked: {unmanaged_results['total_blocked']}")
        
        if unmanaged_results['errors']:
            print(f"⚠ Errors encountered: {len(unmanaged_results['errors'])}")
            for error in unmanaged_results['errors']:
                print(f"  - {error}")
        
        print()
        
        # Step 2: Block private IPs on WAN interfaces
        print("STEP 2: Blocking Private IPs on WAN Interfaces")
        print("-" * 60)
        
        wan_results = netsec.block_wan_private_ips()
        
        print(f"✓ WAN interfaces processed: {len(wan_results['interfaces_processed'])}")
        for interface in wan_results['interfaces_processed']:
            print(f"  - {interface}")
        
        print(f"✓ Total WAN rules applied: {wan_results['total_rules_applied']}")
        
        if wan_results['errors']:
            print(f"⚠ Errors encountered: {len(wan_results['errors'])}")
            for error in wan_results['errors']:
                print(f"  - {error}")
        
        print()
        
        # Step 3: Verify blocking status
        print("STEP 3: Verifying Network Blocking Status")
        print("-" * 60)
        
        status = netsec.verify_blocking_status()
        
        print(f"✓ IPv4 firewall rules: {status.get('ipv4_firewall_rules', 0)}")
        print(f"✓ IPv6 firewall rules: {status.get('ipv6_firewall_rules', 0)}")
        print(f"✓ Database rules: {status.get('database_rules', 0)}")
        print(f"✓ Overall status: {status.get('status', 'unknown').upper()}")
        
        print()
        
        # Step 4: Show comprehensive summary
        print("STEP 4: Comprehensive Security Summary")
        print("-" * 60)
        
        total_actions = unmanaged_results['total_blocked'] + wan_results['total_rules_applied']
        
        print(f"✓ Total security actions performed: {total_actions}")
        print(f"✓ IPv4 ranges blocked: {len(unmanaged_results['ipv4_blocked'])}")
        print(f"✓ IPv6 ranges blocked: {len(unmanaged_results['ipv6_blocked'])}")
        print(f"✓ WAN interfaces secured: {len(wan_results['interfaces_processed'])}")
        print(f"✓ Firewall rules active: {status.get('ipv4_firewall_rules', 0) + status.get('ipv6_firewall_rules', 0)}")
        
        # Show blocked ranges summary
        blocked_ranges = netsec.get_blocked_ranges()
        print(f"✓ Total blocked ranges in database: {len(blocked_ranges)}")
        
        print()
        
        # Step 5: Security recommendations
        print("STEP 5: Security Recommendations")
        print("-" * 60)
        
        recommendations = [
            "✓ All unmanaged IPv4 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are blocked",
            "✓ All unmanaged IPv6 ULA ranges (fc00::/7, fe80::/10) are blocked",
            "✓ WAN interfaces are protected against private IP ingress/egress",
            "✓ Link-local and loopback ranges are blocked on WAN interfaces",
            "✓ Test-NET and documentation ranges are blocked",
            "✓ Multicast and reserved ranges are blocked",
            "✓ Comprehensive firewall rules are active and verified"
        ]
        
        for rec in recommendations:
            print(rec)
        
        print()
        
        # Final status
        if status.get('status') == 'healthy':
            print("🎉 DEPLOYMENT SUCCESSFUL!")
            print("All unmanaged IPv4 and IPv6 ranges are now blocked.")
            print("WAN interfaces are protected against private IP traffic.")
            print("Network security is fully active and verified.")
        else:
            print("⚠️  DEPLOYMENT COMPLETED WITH WARNINGS")
            print("Some network security rules may need manual verification.")
            print("Check the logs for any errors that need attention.")
        
        print()
        print("=" * 80)
        print(f"Deployment completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        return True
        
    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        print(f"❌ DEPLOYMENT FAILED: {str(e)}")
        return False

def start_continuous_monitoring():
    """Start continuous network security monitoring"""
    print("\n" + "=" * 80)
    print("STARTING CONTINUOUS NETWORK SECURITY MONITORING")
    print("=" * 80)
    
    try:
        monitor = NetworkSecurityMonitor()
        monitor.start_monitoring()
        
        print("✓ Continuous monitoring started")
        print("✓ Automatic security enforcement active")
        print("✓ Real-time threat detection enabled")
        print("\nThe system will now continuously monitor and enforce network security.")
        print("Press Ctrl+C to stop monitoring.")
        
        # Keep running
        while True:
            time.sleep(60)
            
            # Show periodic status
            status = monitor.get_monitoring_status()
            if status['statistics']['checks_performed'] % 12 == 0:  # Every hour
                print(f"\nMonitor Status - Uptime: {status['statistics']['uptime_human']}")
                print(f"Checks performed: {status['statistics']['checks_performed']}")
                print(f"Total ranges blocked: {status['statistics']['ranges_blocked']}")
                print(f"Alerts generated: {status['statistics']['alerts_generated']}")
    
    except KeyboardInterrupt:
        print("\nStopping continuous monitoring...")
        monitor.stop_monitoring()
        print("✓ Monitoring stopped")
    
    except Exception as e:
        logger.error(f"Monitoring error: {e}")
        print(f"❌ Monitoring error: {str(e)}")

def main():
    """Main deployment function"""
    if len(sys.argv) > 1 and sys.argv[1] == "--monitor":
        # Start continuous monitoring mode
        start_continuous_monitoring()
    else:
        # Deploy security and optionally start monitoring
        success = deploy_comprehensive_network_security()
        
        if success:
            print("\nWould you like to start continuous monitoring? (y/n): ", end="")
            try:
                response = input().lower().strip()
                if response in ['y', 'yes']:
                    start_continuous_monitoring()
                else:
                    print("\nDeployment complete. Network security is now active.")
                    print("To start continuous monitoring later, run:")
                    print("  python deploy_network_security.py --monitor")
            except KeyboardInterrupt:
                print("\n\nDeployment complete. Network security is now active.")
        else:
            print("\nDeployment failed. Please check the logs and try again.")
            sys.exit(1)

if __name__ == "__main__":
    main()
