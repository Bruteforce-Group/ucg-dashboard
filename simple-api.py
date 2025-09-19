#!/usr/bin/env python3
"""
Simplified AI Security Dashboard API Server
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
import json
from datetime import datetime, timedelta
import logging
import random

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SecurityAPI')

app = Flask(__name__)
CORS(app)  # Enable CORS for dashboard access

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

@app.route('/api/metrics')
def get_metrics():
    """Get current security metrics for dashboard"""
    # Add small random variations to simulate live data
    current_metrics['threats_today'] += random.randint(0, 2)
    current_metrics['queries_per_min'] = 1200 + random.randint(0, 100)
    current_metrics['cpu_usage'] = 20 + random.randint(0, 15)
    
    return jsonify({
        'status': 'success',
        'data': current_metrics,
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

@app.route('/api/ai-simulate')
def simulate_threat():
    """Manually trigger AI threat simulation for testing"""
    
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
        },
        {
            'source_ip': f"10.0.0.{random.randint(10, 50)}",
            'threat_type': 'Malware C&C',
            'risk_level': 'High',
            'details': 'Simulated malware communication'
        }
    ]
    
    scenario = random.choice(scenarios)
    
    # Update metrics
    current_metrics['threats_today'] += 1
    if 'malware' in scenario['threat_type'].lower():
        current_metrics['malware_blocks'] += 1
    
    # Simulate AI processing result
    result = {
        'detection_id': random.randint(1000, 9999),
        'analysis': {
            'final_risk_score': 3.2,
            'recommended_action': 'IMMEDIATE_BLOCK_AND_ALERT',
            'confidence': random.uniform(85.0, 98.0)
        },
        'action_taken': f"IP {scenario['source_ip']} blocked automatically by AI",
        'ai_confidence': random.uniform(85.0, 98.0)
    }
    
    logger.info(f"AI simulated threat: {scenario['threat_type']} from {scenario['source_ip']}")
    
    return jsonify({
        'status': 'success',
        'message': 'AI threat simulation triggered',
        'data': result,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/ai-actions', methods=['POST'])
def trigger_ai_action():
    """Manually trigger AI security actions"""
    try:
        data = request.json
        action_type = data.get('action_type')
        target_ip = data.get('target_ip', '')
        
        if action_type == 'enhance_filtering':
            logger.info("AI enhanced DNS filtering activated")
            return jsonify({
                'status': 'success',
                'message': 'Enhanced DNS filtering activated by AI',
                'timestamp': datetime.now().isoformat()
            })
        elif action_type == 'block_ip' and target_ip:
            logger.info(f"AI blocked IP: {target_ip}")
            return jsonify({
                'status': 'success',
                'message': f'IP {target_ip} blocked by AI security engine',
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

@app.route('/api/detections')
def get_detections():
    """Get recent threat detections with AI analysis"""
    
    # Simulate recent detections
    detections = [
        {
            'id': 101,
            'timestamp': (datetime.now() - timedelta(minutes=5)).isoformat(),
            'source_ip': '192.168.1.45',
            'threat_type': 'Port Scan',
            'risk_level': 'Medium',
            'action_taken': 'Rate limited by AI',
            'details': 'Persistent scanning detected'
        },
        {
            'id': 102,
            'timestamp': (datetime.now() - timedelta(minutes=12)).isoformat(),
            'source_ip': '203.0.113.42',
            'threat_type': 'Brute Force',
            'risk_level': 'High',
            'action_taken': 'IP blocked by AI for 24 hours',
            'details': 'SSH brute force attempt'
        },
        {
            'id': 103,
            'timestamp': (datetime.now() - timedelta(minutes=18)).isoformat(),
            'source_ip': '192.168.1.78',
            'threat_type': 'Malware C&C',
            'risk_level': 'High',
            'action_taken': 'IP blocked by AI for 7 days, DNS filtering enhanced',
            'details': 'Communication with known botnet'
        }
    ]
    
    ai_summary = {
        'total_detections': len(detections),
        'high_risk_count': sum(1 for d in detections if d['risk_level'] == 'High'),
        'auto_blocked_count': sum(1 for d in detections if 'blocked' in d['action_taken']),
        'ai_accuracy': 94.7
    }
    
    return jsonify({
        'status': 'success',
        'data': {
            'detections': detections,
            'ai_summary': ai_summary
        },
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    logger.info("Starting UCG-Fiber AI Security Dashboard API Server...")
    app.run(debug=True, host='0.0.0.0', port=8001)
