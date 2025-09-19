#!/usr/bin/env python3
"""
UCG-Fiber AI Security Dashboard API Server
Provides real-time data and AI analysis to the web dashboard
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
import json
from datetime import datetime, timedelta
import logging
from security_ai import SecurityAI
from network_security import UCGNetworkSecurity
from unifi_network_security import UniFiNetworkSecurity

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SecurityAPI')

app = Flask(__name__)
CORS(app)  # Enable CORS for dashboard access

# Initialize AI engine and Network Security
security_ai = SecurityAI()
network_security = UCGNetworkSecurity()
unifi_network_security = UniFiNetworkSecurity()

# Simulated real-time data
current_metrics = {
    'queries_per_min': 1247,
    'monthly_usage': 7972,
    'cache_hit_rate': 87,
    'threats_today': 237,
    'phishing_blocks': 45,
    'malware_blocks': 89,
    'response_time': 12,
    'cpu_usage': 23,
    'memory_usage': 342,
    'uptime_days': 7,
    'uptime_hours': 14
}

# AI-powered threat simulation thread
def ai_threat_monitor():
    """Background thread that simulates real-time threat detection and AI analysis"""
    threat_scenarios = [
        {
            'source_ip': '192.168.1.45',
            'threat_type': 'Port Scan',
            'risk_level': 'Medium',
            'details': 'Persistent scanning detected on ports 22, 80, 443'
        },
        {
            'source_ip': '203.0.113.42',
            'threat_type': 'Brute Force',
            'risk_level': 'High',
            'details': 'SSH brute force attack targeting admin accounts'
        },
        {
            'source_ip': '192.168.1.78',
            'threat_type': 'Malware C&C',
            'risk_level': 'High',
            'details': 'Communication with known botnet command server detected'
        },
        {
            'source_ip': '10.0.0.15',
            'threat_type': 'Suspicious DNS',
            'risk_level': 'Low',
            'details': 'Unusual DNS query patterns for DGA domains'
        },
        {
            'source_ip': '172.16.0.25',
            'threat_type': 'Data Exfiltration',
            'risk_level': 'Critical',
            'details': 'Large volume data transfer to suspicious external server'
        }
    ]
    
    while True:
        try:
            # Process a random threat every 30-60 seconds
            import random
            time.sleep(random.randint(30, 60))
            
            scenario = random.choice(threat_scenarios)
            logger.info(f"AI detected new threat: {scenario['threat_type']} from {scenario['source_ip']}")
            
            # Process through AI engine
            result = security_ai.process_detection(scenario)
            
            # Update global metrics
            current_metrics['threats_today'] += 1
            if 'phishing' in scenario['threat_type'].lower():
                current_metrics['phishing_blocks'] += 1
            elif 'malware' in scenario['threat_type'].lower():
                current_metrics['malware_blocks'] += 1
                
        except Exception as e:
            logger.error(f"Error in AI threat monitor: {e}")

# Start background AI monitoring
ai_thread = threading.Thread(target=ai_threat_monitor, daemon=True)
ai_thread.start()

@app.route('/api/metrics')
def get_metrics():
    """Get current security metrics for dashboard"""
    return jsonify({
        'status': 'success',
        'data': current_metrics,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/detections')
def get_detections():
    """Get recent threat detections with AI analysis"""
    hours = request.args.get('hours', 24, type=int)
    detections = security_ai.get_recent_detections(hours)
    
    # Add AI analysis summary
    ai_summary = {
        'total_detections': len(detections),
        'high_risk_count': sum(1 for d in detections if d['risk_level'].lower() == 'high'),
        'auto_blocked_count': sum(1 for d in detections if 'blocked' in d.get('action_taken', '').lower()),
        'ai_accuracy': 94.7  # Simulated AI accuracy metric
    }
    
    return jsonify({
        'status': 'success',
        'data': {
            'detections': detections,
            'ai_summary': ai_summary
        },
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/ai-analysis')
def get_ai_analysis():
    """Get AI threat analysis and recommendations"""
    
    # Generate AI insights
    insights = [
        {
            'type': 'trend_analysis',
            'severity': 'medium',
            'title': 'Increased Port Scanning Activity',
            'description': 'AI detected 23% increase in port scanning attempts over the last 6 hours',
            'recommendation': 'Consider implementing adaptive rate limiting',
            'confidence': 87.3
        },
        {
            'type': 'behavioral_anomaly',
            'severity': 'high',
            'title': 'Unusual DNS Query Pattern',
            'description': 'Machine learning models identified suspicious DNS tunneling behavior',
            'recommendation': 'Enhanced DNS monitoring has been automatically activated',
            'confidence': 92.1
        },
        {
            'type': 'predictive_alert',
            'severity': 'low',
            'title': 'Potential Coordinated Attack',
            'description': 'AI correlation engine suggests possible multi-vector attack preparation',
            'recommendation': 'Increased monitoring on network segments 192.168.1.0/24',
            'confidence': 76.8
        }
    ]
    
    return jsonify({
        'status': 'success',
        'data': {
            'insights': insights,
            'ai_status': 'active',
            'model_version': '2.1.4',
            'last_training': '2024-01-15T10:30:00Z'
        },
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/blocked-ips')
def get_blocked_ips():
    """Get currently blocked IPs"""
    try:
        import sqlite3
        conn = sqlite3.connect(security_ai.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ip, reason, blocked_at, expires_at 
            FROM blocked_ips 
            WHERE expires_at > datetime('now')
            ORDER BY blocked_at DESC
        ''')
        
        blocked_ips = []
        for row in cursor.fetchall():
            blocked_ips.append({
                'ip': row[0],
                'reason': row[1],
                'blocked_at': row[2],
                'expires_at': row[3]
            })
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'data': {
                'blocked_ips': blocked_ips,
                'total_blocked': len(blocked_ips)
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/ai-actions', methods=['POST'])
def trigger_ai_action():
    """Manually trigger AI security actions"""
    try:
        data = request.json
        action_type = data.get('action_type')
        target_ip = data.get('target_ip', '')
        
        if action_type == 'block_ip' and target_ip:
            # Use AI engine to block IP
            detection_data = {
                'source_ip': target_ip,
                'threat_type': 'Manual Block',
                'risk_level': 'High',
                'details': 'Manually triggered by security admin'
            }
            
            result = security_ai.process_detection(detection_data)
            
            return jsonify({
                'status': 'success',
                'data': result,
                'timestamp': datetime.now().isoformat()
            })
            
        elif action_type == 'enhance_filtering':
            # Trigger enhanced filtering
            security_ai._enhance_dns_filtering()
            
            return jsonify({
                'status': 'success',
                'message': 'Enhanced DNS filtering activated',
                'timestamp': datetime.now().isoformat()
            })
            
        else:
            return jsonify({
                'status': 'error',
                'message': 'Invalid action type or missing parameters'
            }), 400
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/traffic-analysis')
def get_traffic_analysis():
    """Get detailed traffic analysis data"""
    
    # Simulate real traffic analysis data
    traffic_data = {
        'real_time': {
            'current_qps': 21,
            'peak_today': '1,847/min',
            'cache_efficiency': 87.3,
            'trend': '+2.1%'
        },
        'top_domains': [
            {'domain': 'apple.com', 'queries': 2847, 'status': 'allowed'},
            {'domain': 'google.com', 'queries': 1923, 'status': 'allowed'},
            {'domain': 'microsoft.com', 'queries': 1456, 'status': 'allowed'},
            {'domain': 'facebook.com', 'queries': 1234, 'status': 'filtered'},
            {'domain': 'netflix.com', 'queries': 892, 'status': 'allowed'}
        ],
        'traffic_breakdown': {
            'business': 43,
            'personal': 31,
            'system_updates': 18,
            'blocked': 8
        },
        'historical': {
            'seven_day_avg': '1,183/min',
            'monthly_growth': '+12.4%',
            'busiest_hour': '9:00-10:00 AM'
        }
    }
    
    return jsonify({
        'status': 'success',
        'data': traffic_data,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/security-analysis')
def get_security_analysis():
    """Get detailed security analysis data"""
    
    security_data = {
        'todays_threats': {
            'malware_blocks': 89,
            'malware_trend': '-15%',
            'phishing_attempts': 45,
            'phishing_trend': '+8%',
            'adult_content': 67,
            'gambling': 23
        },
        'ips_detections': [
            {
                'time': '11:42 AM',
                'source': '192.168.1.45',
                'threat_type': 'Port Scan',
                'risk': 'Medium'
            },
            {
                'time': '11:38 AM',
                'source': 'External',
                'threat_type': 'Brute Force',
                'risk': 'High'
            },
            {
                'time': '11:15 AM',
                'source': '192.168.1.78',
                'threat_type': 'Malware C&C',
                'risk': 'High'
            },
            {
                'time': '10:52 AM',
                'source': '192.168.1.23',
                'threat_type': 'Suspicious DNS',
                'risk': 'Low'
            }
        ],
        'blocked_categories': {
            'adult_content': 'Active',
            'gambling': 'Active',
            'malware': 'Active',
            'phishing': 'Active',
            'social_media': 'Partial',
            'advertisement': 'Active'
        },
        'protection_trends': {
            'weekly_blocks': 1847,
            'weekly_trend': '-5.2%',
            'false_positives': '0.3%',
            'response_time': '2.4ms'
        }
    }
    
    return jsonify({
        'status': 'success',
        'data': security_data,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/system-status')
def get_system_status():
    """Get system status information"""
    
    status_data = {
        'services': {
            'coredns': 'Running',
            'suricata_ips': 'Active',
            'ai_engine': 'Active'
        },
        'stats': {
            'filter_categories': 48,
            'allowlist_domains': 171,
            'blocked_ips': len(security_ai.blocked_ips),
            'ai_rules': 15
        },
        'performance': {
            'response_time': f"{current_metrics['response_time']}ms",
            'uptime': f"{current_metrics['uptime_days']} days, {current_metrics['uptime_hours']} hours",
            'memory_usage': f"{current_metrics['memory_usage']}MB",
            'cpu_usage': f"{current_metrics['cpu_usage']}%"
        }
    }
    
    return jsonify({
        'status': 'success',
        'data': status_data,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/ai-simulate')
def simulate_threat():
    """Manually trigger AI threat simulation for testing"""
    import random
    
    scenarios = [
        {
            'source_ip': f"192.168.1.{random.randint(10, 100)}",
            'threat_type': 'Port Scan',
            'risk_level': 'Medium',
            'details': 'Simulated port scanning activity'
        },
        {
            'source_ip': f"203.0.113.{random.randint(1, 50)}",
            'threat_type': 'Brute Force',
            'risk_level': 'High',
            'details': 'Simulated SSH brute force attack'
        }
    ]
    
    scenario = random.choice(scenarios)
    result = security_ai.process_detection(scenario)
    
    return jsonify({
        'status': 'success',
        'message': 'AI threat simulation triggered',
        'data': result,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/network-security/block-unmanaged')
def block_unmanaged_ranges():
    """Block all unmanaged IPv4 and IPv6 ranges"""
    try:
        interface = request.args.get('interface', 'wan')
        results = network_security.block_unmanaged_ranges(interface)
        
        return jsonify({
            'status': 'success',
            'data': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/network-security/block-wan-private')
def block_wan_private_ips():
    """Block private IPs on WAN interfaces"""
    try:
        results = network_security.block_wan_private_ips()
        
        return jsonify({
            'status': 'success',
            'data': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/network-security/blocked-ranges')
def get_blocked_ranges():
    """Get currently blocked network ranges"""
    try:
        ranges = network_security.get_blocked_ranges()
        
        return jsonify({
            'status': 'success',
            'data': {
                'blocked_ranges': ranges,
                'total_blocked': len(ranges),
                'ipv4_count': len([r for r in ranges if r['protocol'] == 'ipv4']),
                'ipv6_count': len([r for r in ranges if r['protocol'] == 'ipv6'])
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/network-security/verify-status')
def verify_blocking_status():
    """Verify network blocking status"""
    try:
        status = network_security.verify_blocking_status()
        
        return jsonify({
            'status': 'success',
            'data': status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/network-security/security-events')
def get_security_events():
    """Get recent network security events"""
    try:
        hours = request.args.get('hours', 24, type=int)
        events = network_security.get_security_events(hours)
        
        return jsonify({
            'status': 'success',
            'data': {
                'security_events': events,
                'total_events': len(events),
                'hours_covered': hours
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/network-security/cleanup', methods=['POST'])
def cleanup_expired_rules():
    """Clean up expired network security rules"""
    try:
        network_security.cleanup_expired_rules()
        
        return jsonify({
            'status': 'success',
            'message': 'Expired rules cleaned up successfully',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/network-security/comprehensive-block', methods=['POST'])
def comprehensive_network_block():
    """Comprehensive blocking of all unmanaged ranges and WAN private IPs"""
    try:
        data = request.json or {}
        interface = data.get('interface', 'wan')
        
        # Block all unmanaged ranges
        unmanaged_results = network_security.block_unmanaged_ranges(interface)
        
        # Block private IPs on WAN interfaces
        wan_results = network_security.block_wan_private_ips()
        
        # Verify status
        status = network_security.verify_blocking_status()
        
        combined_results = {
            'unmanaged_blocking': unmanaged_results,
            'wan_private_blocking': wan_results,
            'verification_status': status,
            'total_actions': unmanaged_results['total_blocked'] + wan_results['total_rules_applied']
        }
        
        logger.info(f"Comprehensive network blocking completed: {combined_results['total_actions']} total actions")
        
        return jsonify({
            'status': 'success',
            'data': combined_results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/unifi-security/authenticate', methods=['POST'])
def authenticate_unifi():
    """Authenticate with UniFi controller"""
    try:
        data = request.json or {}
        username = data.get('username', 'admin')
        password = data.get('password', '')
        host = data.get('host', '192.168.22.1')
        port = data.get('port', 8443)
        
        if not password:
            return jsonify({
                'status': 'error',
                'message': 'Password is required'
            }), 400
        
        # Update UniFi network security with provided credentials
        unifi_network_security.unifi_host = host
        unifi_network_security.unifi_port = port
        unifi_network_security.base_url = f"https://{host}:{port}"
        unifi_network_security.api_url = f"{unifi_network_security.base_url}/api"
        
        success = unifi_network_security.authenticate(username, password)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Successfully authenticated with UniFi controller',
                'data': {
                    'host': host,
                    'port': port,
                    'username': username
                },
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Authentication failed'
            }), 401
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/unifi-security/block-unmanaged')
def unifi_block_unmanaged_ranges():
    """Block all unmanaged IPv4 and IPv6 ranges using UniFi firewall rules"""
    try:
        results = unifi_network_security.block_unmanaged_ranges()
        
        return jsonify({
            'status': 'success',
            'data': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/unifi-security/block-wan-private')
def unifi_block_wan_private_ips():
    """Block private IPs on WAN interfaces using UniFi firewall rules"""
    try:
        results = unifi_network_security.block_wan_private_ips()
        
        return jsonify({
            'status': 'success',
            'data': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/unifi-security/firewall-rules')
def get_unifi_firewall_rules():
    """Get UniFi firewall rules"""
    try:
        rules = unifi_network_security.get_firewall_rules()
        
        return jsonify({
            'status': 'success',
            'data': {
                'firewall_rules': rules,
                'total_rules': len(rules),
                'ipv4_count': len([r for r in rules if '.' in r['source_address']]),
                'ipv6_count': len([r for r in rules if ':' in r['source_address']])
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/unifi-security/verify-status')
def unifi_verify_firewall_status():
    """Verify UniFi firewall rules status"""
    try:
        status = unifi_network_security.verify_firewall_status()
        
        return jsonify({
            'status': 'success',
            'data': status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/unifi-security/security-events')
def get_unifi_security_events():
    """Get UniFi security events"""
    try:
        hours = request.args.get('hours', 24, type=int)
        events = unifi_network_security.get_security_events(hours)
        
        return jsonify({
            'status': 'success',
            'data': {
                'security_events': events,
                'total_events': len(events),
                'hours_covered': hours
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/unifi-security/comprehensive-block', methods=['POST'])
def unifi_comprehensive_network_block():
    """Comprehensive blocking using UniFi firewall rules"""
    try:
        # Block all unmanaged ranges
        unmanaged_results = unifi_network_security.block_unmanaged_ranges()
        
        # Block private IPs on WAN interfaces
        wan_results = unifi_network_security.block_wan_private_ips()
        
        # Verify status
        status = unifi_network_security.verify_firewall_status()
        
        combined_results = {
            'unmanaged_blocking': unmanaged_results,
            'wan_private_blocking': wan_results,
            'verification_status': status,
            'total_actions': unmanaged_results['total_blocked'] + wan_results['total_rules']
        }
        
        logger.info(f"UniFi comprehensive network blocking completed: {combined_results['total_actions']} total actions")
        
        return jsonify({
            'status': 'success',
            'data': combined_results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    logger.info("Starting UCG-Fiber AI Security Dashboard API Server...")
    app.run(debug=True, host='0.0.0.0', port=5000)
