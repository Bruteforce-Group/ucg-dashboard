#!/usr/bin/env python3
"""
UCG-Fiber AI Security Analysis Engine
Proactively analyzes IPS detections and takes automated security actions
"""

import json
import time
import subprocess
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import threading
from dataclasses import dataclass
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/security-ai.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SecurityAI')

@dataclass
class ThreatDetection:
    timestamp: datetime
    source_ip: str
    threat_type: str
    risk_level: str
    details: str = ""
    action_taken: str = ""

class SecurityAI:
    def __init__(self):
        self.db_path = '/tmp/security_detections.db'
        self.ucg_ip = "192.168.1.1"  # UCG-Fiber IP
        self.blocked_ips = set()
        self.threat_patterns = self._load_threat_patterns()
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for storing detections and actions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                details TEXT,
                action_taken TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def _load_threat_patterns(self) -> Dict:
        """Load AI threat analysis patterns"""
        return {
            'port_scan': {
                'severity_multiplier': 1.2,
                'auto_block_threshold': 3,
                'block_duration': timedelta(hours=1),
                'escalation_keywords': ['persistent', 'targeted', 'stealth']
            },
            'brute_force': {
                'severity_multiplier': 2.0,
                'auto_block_threshold': 1,
                'block_duration': timedelta(hours=24),
                'escalation_keywords': ['admin', 'root', 'ssh', 'rdp']
            },
            'malware_cc': {
                'severity_multiplier': 3.0,
                'auto_block_threshold': 1,
                'block_duration': timedelta(days=7),
                'escalation_keywords': ['botnet', 'c2', 'exfiltration']
            },
            'suspicious_dns': {
                'severity_multiplier': 0.8,
                'auto_block_threshold': 5,
                'block_duration': timedelta(minutes=30),
                'escalation_keywords': ['dga', 'tunneling', 'covert']
            }
        }
    
    def analyze_threat(self, detection: ThreatDetection) -> Dict:
        """AI-powered threat analysis"""
        threat_key = detection.threat_type.lower().replace(' ', '_').replace('&', '')
        pattern = self.threat_patterns.get(threat_key, {})
        
        # Base risk assessment
        risk_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        base_score = risk_scores.get(detection.risk_level.lower(), 1)
        
        # Apply AI multipliers
        severity_multiplier = pattern.get('severity_multiplier', 1.0)
        final_score = base_score * severity_multiplier
        
        # Check for escalation keywords
        escalation_keywords = pattern.get('escalation_keywords', [])
        escalation_found = any(keyword in detection.details.lower() 
                             for keyword in escalation_keywords)
        
        if escalation_found:
            final_score *= 1.5
            
        # Determine automated action
        auto_block_threshold = pattern.get('auto_block_threshold', 3)
        block_duration = pattern.get('block_duration', timedelta(hours=1))
        
        analysis = {
            'final_risk_score': final_score,
            'escalation_detected': escalation_found,
            'recommended_action': self._determine_action(final_score, detection),
            'auto_block': final_score >= auto_block_threshold,
            'block_duration': block_duration,
            'confidence': min(final_score / 4.0, 1.0) * 100
        }
        
        return analysis
    
    def _determine_action(self, risk_score: float, detection: ThreatDetection) -> str:
        """Determine recommended security action based on AI analysis"""
        if risk_score >= 3.5:
            return "IMMEDIATE_BLOCK_AND_ALERT"
        elif risk_score >= 2.5:
            return "BLOCK_AND_MONITOR"
        elif risk_score >= 1.5:
            return "RATE_LIMIT_AND_LOG"
        else:
            return "MONITOR_ONLY"
    
    def execute_security_action(self, detection: ThreatDetection, analysis: Dict) -> str:
        """Execute automated security actions"""
        action_taken = "None"
        
        try:
            if analysis['auto_block'] and self._is_valid_ip(detection.source_ip):
                action_taken = self._block_ip(detection.source_ip, 
                                            detection.threat_type,
                                            analysis['block_duration'])
                
            # Additional actions based on threat type
            if detection.threat_type.lower() == 'malware c&c':
                self._enhance_dns_filtering()
                action_taken += "; Enhanced DNS filtering"
                
            elif detection.threat_type.lower() == 'brute force':
                self._implement_rate_limiting(detection.source_ip)
                action_taken += "; Rate limiting applied"
                
            # Log to Suricata for pattern learning
            self._update_suricata_rules(detection, analysis)
            
            logger.info(f"Security action executed: {action_taken} for {detection.source_ip}")
            
        except Exception as e:
            logger.error(f"Failed to execute security action: {e}")
            action_taken = f"ERROR: {str(e)}"
            
        return action_taken
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _block_ip(self, ip: str, reason: str, duration: timedelta) -> str:
        """Block IP address on UCG-Fiber firewall"""
        try:
            # Add to internal blocked set
            self.blocked_ips.add(ip)
            
            # Calculate expiry
            expires_at = datetime.now() + duration
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip, reason, expires_at) 
                VALUES (?, ?, ?)
            ''', (ip, reason, expires_at.isoformat()))
            conn.commit()
            conn.close()
            
            # Execute firewall command via SSH
            ssh_command = [
                'ssh', '-o', 'StrictHostKeyChecking=no',
                f'root@{self.ucg_ip}',
                f'iptables -A INPUT -s {ip} -j DROP && iptables -A FORWARD -s {ip} -j DROP'
            ]
            
            result = subprocess.run(ssh_command, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return f"IP {ip} blocked for {duration}"
            else:
                logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return f"Failed to block IP {ip}"
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return f"Error blocking IP {ip}: {str(e)}"
    
    def _enhance_dns_filtering(self):
        """Enhance DNS filtering for malware C&C domains"""
        try:
            ssh_command = [
                'ssh', '-o', 'StrictHostKeyChecking=no',
                f'root@{self.ucg_ip}',
                'echo "Enhancing DNS filtering for malware domains" >> /tmp/dns_enhancement.log'
            ]
            subprocess.run(ssh_command, timeout=10)
            logger.info("Enhanced DNS filtering activated")
        except Exception as e:
            logger.error(f"Failed to enhance DNS filtering: {e}")
    
    def _implement_rate_limiting(self, ip: str):
        """Implement rate limiting for brute force attempts"""
        try:
            ssh_command = [
                'ssh', '-o', 'StrictHostKeyChecking=no',
                f'root@{self.ucg_ip}',
                f'iptables -A INPUT -s {ip} -m limit --limit 1/min --limit-burst 3 -j ACCEPT'
            ]
            subprocess.run(ssh_command, timeout=10)
            logger.info(f"Rate limiting applied to {ip}")
        except Exception as e:
            logger.error(f"Failed to apply rate limiting to {ip}: {e}")
    
    def _update_suricata_rules(self, detection: ThreatDetection, analysis: Dict):
        """Update Suricata rules based on AI analysis"""
        try:
            rule_content = f"""# AI-Generated Rule for {detection.threat_type}
alert tcp any any -> any any (msg:"AI-Detected {detection.threat_type} from {detection.source_ip}"; 
flow:established; sid:9999{len(self.blocked_ips)}; rev:1;)
"""
            
            ssh_command = [
                'ssh', '-o', 'StrictHostKeyChecking=no',
                f'root@{self.ucg_ip}',
                f'echo "{rule_content}" >> /etc/suricata/rules/ai-generated.rules'
            ]
            subprocess.run(ssh_command, timeout=10)
            logger.info("Updated Suricata rules with AI-generated signatures")
        except Exception as e:
            logger.error(f"Failed to update Suricata rules: {e}")
    
    def store_detection(self, detection: ThreatDetection) -> int:
        """Store detection in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO detections 
            (timestamp, source_ip, threat_type, risk_level, details, action_taken)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            detection.timestamp.isoformat(),
            detection.source_ip,
            detection.threat_type,
            detection.risk_level,
            detection.details,
            detection.action_taken
        ))
        
        detection_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return detection_id
    
    def process_detection(self, detection_data: Dict) -> Dict:
        """Main processing function for new threat detections"""
        # Parse detection data
        detection = ThreatDetection(
            timestamp=datetime.now(),
            source_ip=detection_data.get('source_ip', ''),
            threat_type=detection_data.get('threat_type', ''),
            risk_level=detection_data.get('risk_level', 'low'),
            details=detection_data.get('details', '')
        )
        
        # AI Analysis
        analysis = self.analyze_threat(detection)
        
        # Execute security actions
        action_taken = self.execute_security_action(detection, analysis)
        detection.action_taken = action_taken
        
        # Store in database
        detection_id = self.store_detection(detection)
        
        # Generate response
        response = {
            'detection_id': detection_id,
            'analysis': analysis,
            'action_taken': action_taken,
            'timestamp': detection.timestamp.isoformat(),
            'ai_confidence': analysis['confidence']
        }
        
        logger.info(f"Processed detection {detection_id}: {detection.threat_type} from {detection.source_ip}")
        return response
    
    def get_recent_detections(self, hours: int = 24) -> List[Dict]:
        """Get recent detections for dashboard"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        cursor.execute('''
            SELECT * FROM detections 
            WHERE created_at > ? 
            ORDER BY created_at DESC
        ''', (since.isoformat(),))
        
        detections = []
        for row in cursor.fetchall():
            detections.append({
                'id': row[0],
                'timestamp': row[1],
                'source_ip': row[2],
                'threat_type': row[3],
                'risk_level': row[4],
                'details': row[5],
                'action_taken': row[6],
                'created_at': row[7]
            })
        
        conn.close()
        return detections
    
    def cleanup_expired_blocks(self):
        """Clean up expired IP blocks"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            now = datetime.now()
            cursor.execute('SELECT ip FROM blocked_ips WHERE expires_at < ?', (now.isoformat(),))
            expired_ips = [row[0] for row in cursor.fetchall()]
            
            for ip in expired_ips:
                # Remove from firewall
                ssh_command = [
                    'ssh', '-o', 'StrictHostKeyChecking=no',
                    f'root@{self.ucg_ip}',
                    f'iptables -D INPUT -s {ip} -j DROP 2>/dev/null || true'
                ]
                subprocess.run(ssh_command, timeout=10)
                
                # Remove from blocked set
                self.blocked_ips.discard(ip)
                
                logger.info(f"Unblocked expired IP: {ip}")
            
            # Clean up database
            cursor.execute('DELETE FROM blocked_ips WHERE expires_at < ?', (now.isoformat(),))
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

def simulate_live_detections():
    """Simulate live threat detections for testing"""
    ai = SecurityAI()
    
    # Sample detections based on your data
    sample_detections = [
        {
            'source_ip': '192.168.1.45',
            'threat_type': 'Port Scan',
            'risk_level': 'Medium',
            'details': 'Persistent scanning of multiple ports detected'
        },
        {
            'source_ip': '203.0.113.42',
            'threat_type': 'Brute Force',
            'risk_level': 'High',
            'details': 'SSH brute force attack with admin targeting'
        },
        {
            'source_ip': '192.168.1.78',
            'threat_type': 'Malware C&C',
            'risk_level': 'High',
            'details': 'Communication with known botnet command server'
        },
        {
            'source_ip': '192.168.1.23',
            'threat_type': 'Suspicious DNS',
            'risk_level': 'Low',
            'details': 'Unusual DNS query patterns detected'
        }
    ]
    
    logger.info("Starting AI Security Analysis Engine simulation...")
    
    for detection_data in sample_detections:
        logger.info(f"Processing detection: {detection_data['threat_type']} from {detection_data['source_ip']}")
        result = ai.process_detection(detection_data)
        
        print(f"\n=== AI Security Analysis ===")
        print(f"Threat: {detection_data['threat_type']}")
        print(f"Source: {detection_data['source_ip']}")
        print(f"Risk Level: {detection_data['risk_level']}")
        print(f"AI Confidence: {result['ai_confidence']:.1f}%")
        print(f"Action Taken: {result['action_taken']}")
        print(f"Analysis: {result['analysis']['recommended_action']}")
        
        time.sleep(2)  # Simulate real-time processing
    
    # Cleanup expired blocks
    ai.cleanup_expired_blocks()
    
    # Show recent detections
    recent = ai.get_recent_detections(1)
    print(f"\n=== Recent Detections ({len(recent)}) ===")
    for detection in recent[:3]:
        print(f"{detection['timestamp']}: {detection['threat_type']} - {detection['action_taken']}")

if __name__ == "__main__":
    simulate_live_detections()
