# UCG-Fiber Network Security - Comprehensive Range Blocking

## Overview

This implementation provides comprehensive network security for UCG-Fiber devices by blocking all unmanaged IPv4 and IPv6 ranges, with special focus on WAN interfaces using private IPs. The system uses the **UniFi API** to create and manage firewall rules through the built-in UniFi firewall system, not direct Linux iptables commands.

## Key Features

### 🔒 Comprehensive Range Blocking
- **IPv4 Private Ranges**: Blocks all RFC 1918 private address ranges
  - `10.0.0.0/8` (Class A private)
  - `172.16.0.0/12` (Class B private) 
  - `192.168.0.0/16` (Class C private)
- **IPv6 ULA Ranges**: Blocks all Unique Local Addresses
  - `fc00::/7` (Unique Local Addresses)
  - `fe80::/10` (Link-local addresses)
- **Special Ranges**: Blocks test networks, documentation ranges, and reserved addresses

### 🌐 WAN Interface Protection
- **Private IP Blocking**: Prevents private IPs from being used on WAN interfaces
- **Multi-Interface Support**: Protects all WAN interfaces (wan, wan1, wan2, ppp0, eth0, eth1)
- **Bidirectional Blocking**: Blocks both ingress and egress traffic for private ranges

### 📊 Real-time Monitoring
- **Continuous Monitoring**: 24/7 monitoring of network security status
- **Automatic Enforcement**: Automatically re-applies security policies if needed
- **Alert System**: Generates alerts for security events and policy violations
- **Comprehensive Logging**: Detailed logs of all security actions and events

## Files Structure

```
├── unifi_network_security.py    # UniFi API-based network security engine
├── network_security.py          # Legacy Linux iptables-based engine (deprecated)
├── network_monitor.py           # Continuous monitoring system
├── deploy_unifi_security.py     # UniFi API deployment script (recommended)
├── deploy_network_security.py   # Legacy deployment script (deprecated)
├── api-server.py                # Enhanced API with UniFi security endpoints
└── NETWORK_SECURITY_README.md   # This documentation
```

## Quick Start

### 1. UniFi API Deployment (Recommended)
```bash
# Deploy comprehensive network security using UniFi API
python deploy_unifi_security.py
```

### 2. View Current Firewall Rules
```bash
# Show current UniFi firewall rules
python deploy_unifi_security.py --show-rules
```

### 3. UniFi API Endpoints (Recommended)
The enhanced API server provides the following UniFi-specific endpoints:

- `POST /api/unifi-security/authenticate` - Authenticate with UniFi controller
- `GET /api/unifi-security/block-unmanaged` - Block all unmanaged ranges via UniFi
- `GET /api/unifi-security/block-wan-private` - Block private IPs on WAN via UniFi
- `GET /api/unifi-security/firewall-rules` - Get UniFi firewall rules
- `GET /api/unifi-security/verify-status` - Verify UniFi firewall status
- `GET /api/unifi-security/security-events` - Get UniFi security events
- `POST /api/unifi-security/comprehensive-block` - Comprehensive UniFi blocking

### 4. Legacy API Endpoints (Deprecated)
The legacy Linux iptables-based endpoints are still available but not recommended:

- `GET /api/network-security/block-unmanaged` - Block all unmanaged ranges (iptables)
- `GET /api/network-security/block-wan-private` - Block private IPs on WAN (iptables)
- `GET /api/network-security/blocked-ranges` - Get currently blocked ranges
- `GET /api/network-security/verify-status` - Verify blocking status
- `POST /api/network-security/comprehensive-block` - Comprehensive blocking (iptables)

## Blocked Network Ranges

### IPv4 Ranges
| Range | Description | Reason |
|-------|-------------|---------|
| `10.0.0.0/8` | Class A Private | RFC 1918 - Unmanaged private range |
| `172.16.0.0/12` | Class B Private | RFC 1918 - Unmanaged private range |
| `192.168.0.0/16` | Class C Private | RFC 1918 - Unmanaged private range |
| `169.254.0.0/16` | Link-Local | RFC 3927 - Auto-assigned addresses |
| `127.0.0.0/8` | Loopback | System reserved |
| `0.0.0.0/8` | Current Network | RFC 1122 - Reserved |
| `224.0.0.0/4` | Multicast | RFC 3171 - Multicast addresses |
| `240.0.0.0/4` | Reserved | RFC 1112 - Reserved for future use |
| `192.0.2.0/24` | Test-NET-1 | RFC 3330 - Documentation |
| `198.51.100.0/24` | Test-NET-2 | RFC 3330 - Documentation |
| `203.0.113.0/24` | Test-NET-3 | RFC 3330 - Documentation |
| `198.18.0.0/15` | Benchmarking | RFC 2544 - Network testing |

### IPv6 Ranges
| Range | Description | Reason |
|-------|-------------|---------|
| `fc00::/7` | Unique Local Addresses | RFC 4193 - ULA range |
| `fe80::/10` | Link-Local | RFC 4291 - Auto-assigned |
| `::1/128` | Loopback | RFC 4291 - System reserved |
| `ff00::/8` | Multicast | RFC 4291 - Multicast addresses |
| `2001:db8::/32` | Documentation | RFC 3849 - Documentation |
| `::/128` | Unspecified | RFC 4291 - Reserved |
| `::ffff:0:0/96` | IPv4-mapped | RFC 4291 - IPv4 mapping |
| `64:ff9b::/96` | IPv4-IPv6 Translation | RFC 6052 - Translation |

## UniFi Firewall Rules Applied

### IPv4 Rules (UniFi API)
```python
# UniFi firewall rule structure for IPv4 private ranges
firewall_rule = {
    "name": "Block_IPv4_Private_10_0_0_0_8",
    "description": "Block unmanaged IPv4 private range: 10.0.0.0/8",
    "enabled": True,
    "action": "drop",
    "protocol": "all",
    "source_address": "10.0.0.0/8",
    "dest_address": "any",
    "ruleset": "WAN_IN",  # Apply to WAN inbound traffic
    "logging": True
}
```

### IPv6 Rules (UniFi API)
```python
# UniFi firewall rule structure for IPv6 ULA ranges
firewall_rule = {
    "name": "Block_IPv6_Private_fc00__7",
    "description": "Block unmanaged IPv6 private range: fc00::/7",
    "enabled": True,
    "action": "drop",
    "protocol": "all",
    "source_address": "fc00::/7",
    "dest_address": "any",
    "ruleset": "WAN_IN",  # Apply to WAN inbound traffic
    "logging": True
}
```

### Legacy Linux Rules (Deprecated)
The legacy implementation used direct iptables commands, but this is not recommended for UniFi devices:

```bash
# DEPRECATED: Direct iptables commands (not recommended for UniFi)
iptables -I FORWARD -i wan -s 10.0.0.0/8 -j DROP
ip6tables -I FORWARD -i wan -s fc00::/7 -j DROP
```

## Security Benefits

### 🛡️ Protection Against
- **Private IP Leakage**: Prevents private IPs from appearing on WAN interfaces
- **Network Reconnaissance**: Blocks scanning of private address spaces
- **Traffic Spoofing**: Prevents use of reserved and test network ranges
- **IPv6 Privacy Issues**: Blocks ULA and link-local addresses on WAN
- **Documentation Range Abuse**: Prevents use of test/documentation networks

### 🔍 Monitoring Capabilities
- **Real-time Status**: Continuous monitoring of firewall rule effectiveness
- **Event Logging**: Comprehensive logging of all security events
- **Automatic Recovery**: Automatic re-application of rules if needed
- **Performance Tracking**: Statistics on blocked ranges and security events

## Configuration

### UCG-Fiber Device Settings
```python
# Default configuration
UCG_IP = "192.168.22.1"  # UCG-Fiber device IP
API_ENDPOINT = "http://localhost:5000"  # API server endpoint
CHECK_INTERVAL = 300  # Monitoring check interval (seconds)
```

### Customization
You can customize the blocked ranges by modifying the lists in `network_security.py`:

```python
# Add custom ranges to block
self.unmanaged_ipv4_ranges.append("192.168.100.0/24")
self.unmanaged_ipv6_ranges.append("2001:db8:custom::/48")
```

## Troubleshooting

### Common Issues

1. **SSH Connection Failed**
   - Ensure SSH access to UCG-Fiber device is configured
   - Check SSH key authentication
   - Verify device IP address

2. **Rules Not Applied**
   - Check iptables/ip6tables permissions
   - Verify UCG-Fiber device supports the commands
   - Check for existing conflicting rules

3. **Monitoring Not Working**
   - Verify API server is running
   - Check database permissions
   - Review log files for errors

### Log Files
- `/tmp/network-security.log` - Core security engine logs
- `/tmp/network-monitor.log` - Monitoring system logs
- `/tmp/network-security-deploy.log` - Deployment logs

### Verification Commands
```bash
# Check IPv4 firewall rules
ssh root@192.168.22.1 "iptables -L -n | grep DROP"

# Check IPv6 firewall rules  
ssh root@192.168.22.1 "ip6tables -L -n | grep DROP"

# Verify blocked ranges in database
sqlite3 /tmp/network_security.db "SELECT * FROM blocked_ranges;"
```

## API Usage Examples

### Block All Unmanaged Ranges
```bash
curl -X GET "http://localhost:5000/api/network-security/block-unmanaged?interface=wan"
```

### Get Blocking Status
```bash
curl -X GET "http://localhost:5000/api/network-security/verify-status"
```

### Comprehensive Blocking
```bash
curl -X POST "http://localhost:5000/api/network-security/comprehensive-block" \
  -H "Content-Type: application/json" \
  -d '{"interface": "wan"}'
```

## Security Considerations

⚠️ **Important Notes**:
- This system blocks legitimate private network traffic on WAN interfaces
- Ensure your network topology doesn't require private IPs on WAN
- Test thoroughly in a lab environment before production deployment
- Monitor logs for any legitimate traffic being blocked
- Consider whitelist exceptions for specific use cases

## Support

For issues or questions:
1. Check the log files for detailed error information
2. Verify UCG-Fiber device connectivity and SSH access
3. Review the API endpoints for status information
4. Use the verification commands to check rule application

## Version History

- **v1.0** - Initial implementation with comprehensive IPv4/IPv6 blocking
- **v1.1** - Added continuous monitoring and automatic enforcement
- **v1.2** - Enhanced API endpoints and deployment automation
