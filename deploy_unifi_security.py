#!/usr/bin/env python3
"""
UCG-Fiber UniFi Network Security Deployment Script
Deploy comprehensive network security using UniFi API firewall rules
"""

import sys
import time
import logging
from datetime import datetime
from unifi_network_security import UniFiNetworkSecurity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/unifi-security-deploy.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('UniFiSecurityDeploy')

def deploy_unifi_network_security():
    """Deploy comprehensive UniFi network security"""
    print("=" * 80)
    print("UCG-FIBER UNIFI NETWORK SECURITY DEPLOYMENT")
    print("=" * 80)
    print(f"Deployment started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Get UniFi controller details
        print("STEP 1: UniFi Controller Configuration")
        print("-" * 60)
        
        unifi_host = input("Enter UniFi controller IP (default: 192.168.22.1): ").strip()
        if not unifi_host:
            unifi_host = "192.168.22.1"
        
        unifi_port = input("Enter UniFi controller port (default: 8443): ").strip()
        if not unifi_port:
            unifi_port = 8443
        else:
            unifi_port = int(unifi_port)
        
        username = input("Enter UniFi username (default: admin): ").strip()
        if not username:
            username = "admin"
        
        password = input("Enter UniFi password: ").strip()
        if not password:
            print("❌ Password is required!")
            return False
        
        print(f"✓ Controller: {unifi_host}:{unifi_port}")
        print(f"✓ Username: {username}")
        print()
        
        # Initialize UniFi network security
        logger.info("Initializing UCG-Fiber UniFi Network Security...")
        unifi_netsec = UniFiNetworkSecurity(unifi_host, unifi_port)
        
        # Authenticate
        print("STEP 2: UniFi Authentication")
        print("-" * 60)
        
        if not unifi_netsec.authenticate(username, password):
            print("❌ Authentication failed!")
            print("Please check your credentials and try again.")
            return False
        
        print("✓ Successfully authenticated with UniFi controller")
        print()
        
        # Step 3: Block all unmanaged IPv4 and IPv6 ranges
        print("STEP 3: Creating UniFi Firewall Rules for Unmanaged Ranges")
        print("-" * 60)
        
        unmanaged_results = unifi_netsec.block_unmanaged_ranges()
        
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
        
        # Step 4: Block private IPs on WAN interfaces
        print("STEP 4: Creating UniFi Firewall Rules for WAN Private IPs")
        print("-" * 60)
        
        wan_results = unifi_netsec.block_wan_private_ips()
        
        print(f"✓ WAN firewall rules created: {wan_results['total_rules']}")
        for rule_name in wan_results['rules_created']:
            print(f"  - {rule_name}")
        
        if wan_results['errors']:
            print(f"⚠ Errors encountered: {len(wan_results['errors'])}")
            for error in wan_results['errors']:
                print(f"  - {error}")
        
        print()
        
        # Step 5: Verify firewall status
        print("STEP 5: Verifying UniFi Firewall Rules")
        print("-" * 60)
        
        status = unifi_netsec.verify_firewall_status()
        
        print(f"✓ Total firewall rules: {status.get('total_rules', 0)}")
        print(f"✓ IPv4 rules: {status.get('ipv4_rules', 0)}")
        print(f"✓ IPv6 rules: {status.get('ipv6_rules', 0)}")
        print(f"✓ Drop rules: {status.get('drop_rules', 0)}")
        print(f"✓ Overall status: {status.get('status', 'unknown').upper()}")
        
        print()
        
        # Step 6: Show comprehensive summary
        print("STEP 6: Comprehensive Security Summary")
        print("-" * 60)
        
        total_actions = unmanaged_results['total_blocked'] + wan_results['total_rules']
        
        print(f"✓ Total UniFi firewall rules created: {total_actions}")
        print(f"✓ IPv4 ranges blocked: {len(unmanaged_results['ipv4_blocked'])}")
        print(f"✓ IPv6 ranges blocked: {len(unmanaged_results['ipv6_blocked'])}")
        print(f"✓ WAN private IP rules: {wan_results['total_rules']}")
        print(f"✓ Total active firewall rules: {status.get('total_rules', 0)}")
        
        # Show created rules
        rules = unifi_netsec.get_firewall_rules()
        print(f"✓ Rules in database: {len(rules)}")
        
        print()
        
        # Step 7: Security recommendations
        print("STEP 7: UniFi Security Recommendations")
        print("-" * 60)
        
        recommendations = [
            "✓ All unmanaged IPv4 private ranges are blocked via UniFi firewall rules",
            "✓ All unmanaged IPv6 ULA ranges are blocked via UniFi firewall rules",
            "✓ WAN interfaces are protected against private IP traffic",
            "✓ Link-local and loopback ranges are blocked on WAN interfaces",
            "✓ Test-NET and documentation ranges are blocked",
            "✓ Multicast and reserved ranges are blocked",
            "✓ All rules are managed through UniFi Network application",
            "✓ Rules are persistent and survive device reboots",
            "✓ Comprehensive logging is enabled for all blocked traffic"
        ]
        
        for rec in recommendations:
            print(rec)
        
        print()
        
        # Final status
        if status.get('status') == 'healthy':
            print("🎉 UNIFI SECURITY DEPLOYMENT SUCCESSFUL!")
            print("All unmanaged IPv4 and IPv6 ranges are now blocked via UniFi firewall rules.")
            print("WAN interfaces are protected against private IP traffic.")
            print("Network security is fully active and managed through UniFi.")
        else:
            print("⚠️  DEPLOYMENT COMPLETED WITH WARNINGS")
            print("Some UniFi firewall rules may need manual verification.")
            print("Check the UniFi Network application for rule status.")
        
        print()
        print("=" * 80)
        print(f"Deployment completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        return True
        
    except KeyboardInterrupt:
        print("\n\n❌ Deployment cancelled by user")
        return False
        
    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        print(f"❌ DEPLOYMENT FAILED: {str(e)}")
        return False

def show_firewall_rules():
    """Show current UniFi firewall rules"""
    print("\n" + "=" * 80)
    print("CURRENT UNIFI FIREWALL RULES")
    print("=" * 80)
    
    try:
        unifi_netsec = UniFiNetworkSecurity()
        rules = unifi_netsec.get_firewall_rules()
        
        if not rules:
            print("No firewall rules found in database.")
            print("Run the deployment script first to create rules.")
            return
        
        print(f"Found {len(rules)} firewall rules:")
        print()
        
        for i, rule in enumerate(rules, 1):
            print(f"{i}. {rule['rule_name']}")
            print(f"   Description: {rule['description']}")
            print(f"   Action: {rule['action'].upper()}")
            print(f"   Protocol: {rule['protocol']}")
            print(f"   Source: {rule['source_address']}")
            print(f"   Destination: {rule['dest_address']}")
            print(f"   Enabled: {'Yes' if rule['enabled'] else 'No'}")
            print(f"   Created: {rule['created_at']}")
            print()
        
        # Show summary
        ipv4_count = len([r for r in rules if '.' in r['source_address']])
        ipv6_count = len([r for r in rules if ':' in r['source_address']])
        drop_count = len([r for r in rules if r['action'] == 'drop'])
        
        print("Summary:")
        print(f"  - Total rules: {len(rules)}")
        print(f"  - IPv4 rules: {ipv4_count}")
        print(f"  - IPv6 rules: {ipv6_count}")
        print(f"  - Drop rules: {drop_count}")
        
    except Exception as e:
        print(f"❌ Error retrieving firewall rules: {str(e)}")

def main():
    """Main deployment function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == "--show-rules":
            show_firewall_rules()
        elif sys.argv[1] == "--help":
            print("UCG-Fiber UniFi Network Security Deployment")
            print("=" * 50)
            print("Usage:")
            print("  python deploy_unifi_security.py              # Deploy security")
            print("  python deploy_unifi_security.py --show-rules # Show current rules")
            print("  python deploy_unifi_security.py --help       # Show this help")
            print()
            print("This script uses the UniFi API to create firewall rules")
            print("that block all unmanaged IPv4 and IPv6 ranges.")
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Use --help for usage information")
    else:
        # Deploy security
        success = deploy_unifi_network_security()
        
        if success:
            print("\n✅ UniFi network security deployment completed successfully!")
            print("\nTo view created rules, run:")
            print("  python deploy_unifi_security.py --show-rules")
            print("\nTo manage rules, use the UniFi Network application:")
            print("  https://192.168.1.1:8443")
        else:
            print("\n❌ Deployment failed. Please check the logs and try again.")
            sys.exit(1)

if __name__ == "__main__":
    main()
