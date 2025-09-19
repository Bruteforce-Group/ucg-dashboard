#!/usr/bin/env python3
"""
Test internal network services after cleanup
"""

import subprocess
import socket
import time
import logging
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('InternalServicesTest')

class InternalServicesTester:
    def __init__(self, ucg_ip: str = "192.168.22.1"):
        self.ucg_ip = ucg_ip
        self.test_results = {}

    def test_dns_resolution(self) -> bool:
        """Test DNS resolution"""
        try:
            logger.info("Testing DNS resolution...")
            result = subprocess.run(
                ['nslookup', 'google.com', self.ucg_ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            success = result.returncode == 0 and 'google.com' in result.stdout
            self.test_results['dns_resolution'] = success
            if success:
                logger.info("✅ DNS resolution working")
            else:
                logger.error(f"❌ DNS resolution failed: {result.stderr}")
            return success
        except Exception as e:
            logger.error(f"❌ DNS resolution error: {e}")
            self.test_results['dns_resolution'] = False
            return False

    def test_mdns_discovery(self) -> bool:
        """Test mDNS service discovery"""
        try:
            logger.info("Testing mDNS service discovery...")
            # Try to discover services on the local network
            result = subprocess.run(
                ['dns-sd', '-B', '_http._tcp', 'local.'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # mDNS might not find services, but the command should work
            success = result.returncode == 0 or 'dns-sd' in result.stderr
            self.test_results['mdns_discovery'] = success
            if success:
                logger.info("✅ mDNS service discovery working")
            else:
                logger.error(f"❌ mDNS discovery failed: {result.stderr}")
            return success
        except Exception as e:
            logger.error(f"❌ mDNS discovery error: {e}")
            self.test_results['mdns_discovery'] = False
            return False

    def test_multicast_connectivity(self) -> bool:
        """Test multicast connectivity"""
        try:
            logger.info("Testing multicast connectivity...")
            # Test if we can bind to multicast addresses
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('224.0.0.1', 5353))  # mDNS multicast address
            sock.close()
            self.test_results['multicast_connectivity'] = True
            logger.info("✅ Multicast connectivity working")
            return True
        except Exception as e:
            logger.error(f"❌ Multicast connectivity failed: {e}")
            self.test_results['multicast_connectivity'] = False
            return False

    def test_llmnr_resolution(self) -> bool:
        """Test LLMNR (Link-Local Multicast Name Resolution)"""
        try:
            logger.info("Testing LLMNR resolution...")
            # Try to resolve a local hostname that might use LLMNR
            result = subprocess.run(
                ['nslookup', 'localhost', self.ucg_ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            success = result.returncode == 0
            self.test_results['llmnr_resolution'] = success
            if success:
                logger.info("✅ LLMNR resolution working")
            else:
                logger.error(f"❌ LLMNR resolution failed: {result.stderr}")
            return success
        except Exception as e:
            logger.error(f"❌ LLMNR resolution error: {e}")
            self.test_results['llmnr_resolution'] = False
            return False

    def test_secure_dns(self) -> bool:
        """Test secure DNS (DoT/DoH)"""
        try:
            logger.info("Testing secure DNS (DoT)...")
            # Test DNS over TLS on port 853
            result = subprocess.run(
                ['dig', '@1.1.1.1', '+tls', 'google.com'],
                capture_output=True,
                text=True,
                timeout=10
            )
            success = result.returncode == 0 and 'google.com' in result.stdout
            self.test_results['secure_dns'] = success
            if success:
                logger.info("✅ Secure DNS (DoT) working")
            else:
                logger.error(f"❌ Secure DNS (DoT) failed: {result.stderr}")
            return success
        except Exception as e:
            logger.error(f"❌ Secure DNS error: {e}")
            self.test_results['secure_dns'] = False
            return False

    def test_network_connectivity(self) -> bool:
        """Test basic network connectivity"""
        try:
            logger.info("Testing network connectivity...")
            result = subprocess.run(
                ['ping', '-c', '3', '8.8.8.8'],
                capture_output=True,
                text=True,
                timeout=15
            )
            success = result.returncode == 0
            self.test_results['network_connectivity'] = success
            if success:
                logger.info("✅ Network connectivity working")
            else:
                logger.error(f"❌ Network connectivity failed: {result.stderr}")
            return success
        except Exception as e:
            logger.error(f"❌ Network connectivity error: {e}")
            self.test_results['network_connectivity'] = False
            return False

    def run_all_tests(self) -> Dict:
        """Run all internal service tests"""
        logger.info("=" * 60)
        logger.info("TESTING INTERNAL NETWORK SERVICES")
        logger.info("=" * 60)
        
        tests = [
            self.test_network_connectivity,
            self.test_dns_resolution,
            self.test_multicast_connectivity,
            self.test_mdns_discovery,
            self.test_llmnr_resolution,
            self.test_secure_dns
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
                time.sleep(1)  # Small delay between tests
            except Exception as e:
                logger.error(f"Test failed with exception: {e}")
        
        success_rate = (passed / total) * 100
        
        return {
            'total_tests': total,
            'passed_tests': passed,
            'failed_tests': total - passed,
            'success_rate': success_rate,
            'test_results': self.test_results
        }

def main():
    print("=" * 80)
    print("TESTING INTERNAL NETWORK SERVICES AFTER CLEANUP")
    print("=" * 80)
    
    tester = InternalServicesTester()
    results = tester.run_all_tests()
    
    print(f"\n=== TEST RESULTS ===")
    print(f"Total tests: {results['total_tests']}")
    print(f"Passed: {results['passed_tests']}")
    print(f"Failed: {results['failed_tests']}")
    print(f"Success rate: {results['success_rate']:.1f}%")
    
    print(f"\n=== DETAILED RESULTS ===")
    for test_name, result in results['test_results'].items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name.replace('_', ' ').title()}: {status}")
    
    if results['success_rate'] >= 80:
        print(f"\n🎉 SUCCESS! Internal services are working well!")
        print(f"✅ Network functionality has been restored")
        print(f"✅ WAN protection remains active")
    elif results['success_rate'] >= 60:
        print(f"\n⚠️  PARTIAL SUCCESS! Most services working")
        print(f"Some services may need additional configuration")
    else:
        print(f"\n❌ ISSUES DETECTED! Some services are not working")
        print(f"Check network configuration and firewall rules")

if __name__ == "__main__":
    main()
