"""
Unified Threat Response Pipeline

Author: berinabraham-sec
Version: 2.0.0

Description:
    This module implements an end-to-end security operations pipeline that
    simulates the core functions of a modern Security Operations Center.
    The pipeline is designed to demonstrate threat detection, alerting,
    intelligence enrichment, automated response, and comprehensive logging.

Architecture Overview:
    The pipeline consists of six integrated layers that work together to
    process security events from detection through remediation:

    1. Detection Layer: Ingests and analyzes simulated endpoint telemetry
       using pattern matching against a library of detection rules.

    2. Alerting Layer: Generates structured alerts with severity scoring
       and simulates notification delivery to security teams.

    3. Enrichment Layer: Augments alerts with contextual intelligence
       from threat intelligence sources and maintains a cache for
       performance optimization.

    4. Response Layer: Evaluates risk scores and executes appropriate
       response actions including automated containment, escalation,
       and monitoring workflows.

    5. Logging Layer: Maintains a complete audit trail of all events,
       alerts, and response actions in a structured database.

    6. Reporting Layer: Generates comprehensive reports in multiple
       formats suitable for different audiences including security
       analysts, management, and compliance teams.

Integration Capabilities:
    - SIEM Integration: Structured output formats (JSON, CSV) for
      ingestion by SIEM platforms
    - Threat Intelligence: Simulated VirusTotal API integration with
      caching for performance
    - MDM Integration: Simulated device containment via MDM API
    - Collaboration Tools: Simulated Slack webhook notifications
    - MITRE ATT&CK Framework: Mapping of detection rules to techniques
    - Compliance Reporting: Audit-ready logging and reporting

Implementation Notes:
    This is a demonstration implementation that simulates integrations
    with real security tools. The simulation is designed to be realistic
    enough to demonstrate understanding while remaining self-contained
    for portability and ease of demonstration.
"""

import json
import sqlite3
import os
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import sys
import csv
import hashlib
import re


# ============================================================================
# Configuration
# ============================================================================

class Configuration:
    """
    Centralized configuration container for all pipeline settings.
    
    This class serves as a single source of truth for all configurable
    parameters. This design pattern improves maintainability and allows
    for environment-specific overrides without modifying core logic.
    """
    
    # Database Settings
    DATABASE_FILE = "threat_pipeline.db"
    
    # Output Settings
    OUTPUT_DIR = "reports"
    
    # Pipeline Timing Settings
    LOG_SIMULATION_INTERVAL = 1
    MAX_ALERTS_PER_RUN = 10
    
    # Risk Thresholds
    AUTO_CONTAINMENT_THRESHOLD = 7.0
    ESCALATION_THRESHOLD = 5.0
    
    # API Configuration
    VIRUSTOTAL_API_KEY = "demo-api-key"
    SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/demo/webhook"
    MDM_API_ENDPOINT = "https://api.mdm.example.com/v1/devices"
    SPLUNK_HEC_URL = "https://splunk.example.com:8088/services/collector"
    SPLUNK_HEC_TOKEN = "demo-token"
    
    # Risk Scoring Weights
    WEIGHT_MALICIOUS = 5.0
    WEIGHT_SUSPICIOUS = 3.0
    WEIGHT_UNKNOWN = 1.0
    WEIGHT_CRITICAL_SEVERITY = 2.0
    WEIGHT_HIGH_SEVERITY = 1.5
    
    # Detection Rules Library
    DETECTION_RULES = {
        'powershell_abuse': {
            'name': 'PowerShell Abuse',
            'description': 'PowerShell execution with suspicious parameters',
            'severity': 'HIGH',
            'mitre_technique': 'T1059.001',
            'tactic': 'Execution',
            'platform': ['Windows']
        },
        'local_account_creation': {
            'name': 'Local Account Creation',
            'description': 'New local user account was created',
            'severity': 'MEDIUM',
            'mitre_technique': 'T1136.001',
            'tactic': 'Persistence',
            'platform': ['Windows', 'Linux']
        },
        'privilege_escalation': {
            'name': 'Privilege Escalation',
            'description': 'Attempt to escalate privileges detected',
            'severity': 'CRITICAL',
            'mitre_technique': 'T1068',
            'tactic': 'Privilege Escalation',
            'platform': ['Windows', 'Linux', 'macOS']
        },
        'persistence_mechanism': {
            'name': 'Persistence Mechanism',
            'description': 'Suspicious registry or startup modification',
            'severity': 'HIGH',
            'mitre_technique': 'T1547',
            'tactic': 'Persistence',
            'platform': ['Windows']
        },
        'lateral_movement': {
            'name': 'Lateral Movement',
            'description': 'Attempt to move laterally within the network',
            'severity': 'HIGH',
            'mitre_technique': 'T1021',
            'tactic': 'Lateral Movement',
            'platform': ['Windows']
        },
        'data_exfiltration': {
            'name': 'Data Exfiltration',
            'description': 'Suspicious outbound data transfer detected',
            'severity': 'CRITICAL',
            'mitre_technique': 'T1048',
            'tactic': 'Exfiltration',
            'platform': ['Windows', 'Linux', 'macOS']
        },
        'credential_dumping': {
            'name': 'Credential Dumping',
            'description': 'Attempt to dump credentials from system memory',
            'severity': 'CRITICAL',
            'mitre_technique': 'T1003',
            'tactic': 'Credential Access',
            'platform': ['Windows']
        },
        'command_and_control': {
            'name': 'Command and Control',
            'description': 'Suspicious C2 communication detected',
            'severity': 'CRITICAL',
            'mitre_technique': 'T1071',
            'tactic': 'Command and Control',
            'platform': ['Windows', 'Linux', 'macOS']
        },
        'defense_evasion': {
            'name': 'Defense Evasion',
            'description': 'Attempt to disable security controls',
            'severity': 'HIGH',
            'mitre_technique': 'T1562',
            'tactic': 'Defense Evasion',
            'platform': ['Windows', 'Linux', 'macOS']
        },
        'discovery': {
            'name': 'Discovery Activity',
            'description': 'System and network discovery activities',
            'severity': 'MEDIUM',
            'mitre_technique': 'T1082',
            'tactic': 'Discovery',
            'platform': ['Windows', 'Linux', 'macOS']
        }
    }


# ============================================================================
# Database Manager
# ============================================================================

class DatabaseManager:
    """
    Handles all database operations for the pipeline.
    
    This class abstracts the underlying SQLite database and provides
    a clean interface for storing and retrieving pipeline data. It
    maintains three primary tables:
    
    1. events: Raw telemetry and log data
    2. alerts: Structured security alerts with enrichment
    3. response_actions: Audit trail of response actions
    4. threat_intel: Cached threat intelligence results
    """
    
    def __init__(self, db_file: str = Configuration.DATABASE_FILE):
        """
        Initialize the database manager.
        
        Args:
            db_file: Path to the SQLite database file
        """
        self.db_file = db_file
        self._initialize_database()
    
    def _initialize_database(self):
        """
        Create database tables if they do not exist.
        
        This method is called during initialization and ensures
        all required tables are present before any operations
        are performed.
        """
        with sqlite3.connect(self.db_file) as connection:
            cursor = connection.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source TEXT,
                    event_type TEXT,
                    message TEXT,
                    raw_data TEXT,
                    processed INTEGER DEFAULT 0
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    rule_name TEXT,
                    severity TEXT,
                    description TEXT,
                    source_events TEXT,
                    enriched_data TEXT,
                    status TEXT DEFAULT 'NEW',
                    risk_score REAL,
                    containment_status TEXT DEFAULT 'PENDING',
                    investigation_notes TEXT,
                    mitre_technique TEXT,
                    tactic TEXT,
                    confidence_score REAL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS response_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    action_taken TEXT,
                    timestamp TEXT NOT NULL,
                    status TEXT,
                    details TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL,
                    verdict TEXT,
                    last_checked TEXT,
                    details TEXT,
                    indicator_type TEXT DEFAULT 'hash'
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    details TEXT
                )
            """)
            
            connection.commit()
    
    def log_event(self, event: Dict) -> str:
        """
        Record a raw event in the database.
        
        Args:
            event: Dictionary containing event data
            
        Returns:
            str: Unique event identifier
        """
        event_id = hashlib.md5(
            f"{event.get('timestamp', datetime.now().isoformat())}{random.randint(1, 1000000)}".encode()
        ).hexdigest()[:8]
        
        with sqlite3.connect(self.db_file) as connection:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO events (
                    event_id, timestamp, source, event_type, message, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event_id,
                event.get('timestamp', datetime.now().isoformat()),
                event.get('source', 'unknown'),
                event.get('event_type', 'unknown'),
                event.get('message', ''),
                json.dumps(event)
            ))
            connection.commit()
            return event_id
    
    def create_alert(self, alert: Dict) -> str:
        """
        Create a new security alert.
        
        Args:
            alert: Dictionary containing alert data
            
        Returns:
            str: Unique alert identifier
        """
        alert_id = hashlib.md5(
            f"{alert.get('rule_name', 'unknown')}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:8]
        
        with sqlite3.connect(self.db_file) as connection:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO alerts (
                    alert_id, timestamp, rule_name, severity, description,
                    source_events, enriched_data, status, risk_score,
                    containment_status, mitre_technique, tactic, confidence_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id,
                alert.get('timestamp', datetime.now().isoformat()),
                alert.get('rule_name', ''),
                alert.get('severity', 'MEDIUM'),
                alert.get('description', ''),
                json.dumps(alert.get('source_events', [])),
                json.dumps(alert.get('enriched_data', {})),
                alert.get('status', 'NEW'),
                alert.get('risk_score', 0.0),
                alert.get('containment_status', 'PENDING'),
                alert.get('mitre_technique', ''),
                alert.get('tactic', ''),
                alert.get('confidence_score', 0.0)
            ))
            connection.commit()
            return alert_id
    
    def log_response_action(self, alert_id: str, action: str, status: str, details: Dict) -> int:
        """
        Record a response action taken for an alert.
        
        Args:
            alert_id: The alert identifier
            action: The action that was taken
            status: The current status of the action
            details: Additional details about the action
            
        Returns:
            int: The action record identifier
        """
        with sqlite3.connect(self.db_file) as connection:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO response_actions (
                    alert_id, action_taken, timestamp, status, details
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                alert_id,
                action,
                datetime.now().isoformat(),
                status,
                json.dumps(details)
            ))
            
            cursor.execute("""
                UPDATE alerts SET containment_status = ?
                WHERE alert_id = ?
            """, (status, alert_id))
            
            connection.commit()
            return cursor.lastrowid
    
    def cache_threat_intel(self, indicator: str, verdict: str, details: Dict, indicator_type: str = 'hash'):
        """
        Cache threat intelligence results for future lookups.
        
        Args:
            indicator: The indicator being cached (hash, domain, IP)
            verdict: The verdict (malicious, suspicious, clean, unknown)
            details: Additional context about the verdict
            indicator_type: Type of indicator (hash, domain, ip)
        """
        with sqlite3.connect(self.db_file) as connection:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_intel (
                    indicator, verdict, last_checked, details, indicator_type
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                indicator,
                verdict,
                datetime.now().isoformat(),
                json.dumps(details),
                indicator_type
            ))
            connection.commit()
    
    def get_cached_intel(self, indicator: str) -> Optional[Dict]:
        """
        Retrieve cached threat intelligence.
        
        Args:
            indicator: The indicator to look up
            
        Returns:
            Optional[Dict]: Cached intelligence or None if not found
        """
        with sqlite3.connect(self.db_file) as connection:
            connection.row_factory = sqlite3.Row
            cursor = connection.cursor()
            cursor.execute("""
                SELECT * FROM threat_intel WHERE indicator = ?
            """, (indicator,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                result['details'] = json.loads(result['details'])
                return result
            return None
    
    def record_metric(self, metric_name: str, metric_value: float, details: Dict = None):
        """
        Record a pipeline performance metric.
        
        Args:
            metric_name: Name of the metric
            metric_value: Numeric value
            details: Additional context
        """
        with sqlite3.connect(self.db_file) as connection:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO pipeline_metrics (timestamp, metric_name, metric_value, details)
                VALUES (?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                metric_name,
                metric_value,
                json.dumps(details) if details else '{}'
            ))
            connection.commit()
    
    def get_alerts(self, limit: int = 50, severity: str = None) -> List[Dict]:
        """
        Retrieve alerts with optional filtering.
        
        Args:
            limit: Maximum number of alerts to return
            severity: Optional severity filter
            
        Returns:
            List[Dict]: List of alert records
        """
        with sqlite3.connect(self.db_file) as connection:
            connection.row_factory = sqlite3.Row
            cursor = connection.cursor()
            
            query = """
                SELECT * FROM alerts
                ORDER BY timestamp DESC
            """
            params = []
            
            if severity:
                query = """
                    SELECT * FROM alerts
                    WHERE severity = ?
                    ORDER BY timestamp DESC
                """
                params.append(severity)
            
            query += " LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                alert = dict(row)
                alert['source_events'] = json.loads(alert['source_events']) if alert['source_events'] else []
                alert['enriched_data'] = json.loads(alert['enriched_data']) if alert['enriched_data'] else {}
                results.append(alert)
            
            return results
    
    def get_statistics(self) -> Dict:
        """
        Generate comprehensive pipeline statistics.
        
        Returns:
            Dict: Aggregated statistics
        """
        with sqlite3.connect(self.db_file) as connection:
            cursor = connection.cursor()
            
            stats = {}
            
            cursor.execute("SELECT COUNT(*) FROM events")
            stats['total_events'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM alerts")
            stats['total_alerts'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT severity, COUNT(*) FROM alerts GROUP BY severity
            """)
            severity_counts = {}
            for row in cursor.fetchall():
                severity_counts[row[0]] = row[1]
            stats['severity_distribution'] = severity_counts
            
            cursor.execute("""
                SELECT containment_status, COUNT(*) FROM alerts
                WHERE containment_status IS NOT NULL
                GROUP BY containment_status
            """)
            status_counts = {}
            for row in cursor.fetchall():
                status_counts[row[0]] = row[1]
            stats['containment_status'] = status_counts
            
            cursor.execute("SELECT AVG(risk_score) FROM alerts")
            avg_risk = cursor.fetchone()[0]
            stats['average_risk_score'] = round(avg_risk, 2) if avg_risk else 0.0
            
            cursor.execute("SELECT AVG(confidence_score) FROM alerts")
            avg_confidence = cursor.fetchone()[0]
            stats['average_confidence'] = round(avg_confidence, 2) if avg_confidence else 0.0
            
            cursor.execute("""
                SELECT timestamp, metric_name, metric_value
                FROM pipeline_metrics
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            stats['recent_metrics'] = cursor.fetchall()
            
            return stats
    
    def export_for_siem(self, format_type: str = 'json', limit: int = 100) -> str:
        """
        Export alerts in SIEM-compatible format.
        
        Args:
            format_type: 'json' or 'csv'
            limit: Maximum number of alerts to export
            
        Returns:
            str: Formatted export data
        """
        alerts = self.get_alerts(limit=limit)
        
        if format_type == 'json':
            return json.dumps(alerts, indent=2)
        elif format_type == 'csv':
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            
            fields = [
                'alert_id', 'timestamp', 'rule_name', 'severity',
                'description', 'risk_score', 'containment_status',
                'mitre_technique', 'tactic', 'confidence_score'
            ]
            writer.writerow(fields)
            
            for alert in alerts:
                row = [str(alert.get(f, '')) for f in fields]
                writer.writerow(row)
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported format: {format_type}")


# ============================================================================
# Detection Engine
# ============================================================================

class DetectionEngine:
    """
    Detection layer of the threat response pipeline.
    
    This engine simulates ingestion and analysis of endpoint telemetry
    from sources such as osquery and Sysmon. It applies pattern matching
    rules to identify suspicious activity and generates structured alerts.
    
    Key Capabilities:
        - Simulated log generation with realistic patterns
        - Rule-based detection with MITRE mapping
        - Severity scoring based on rule configuration
        - Event correlation and aggregation
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize the detection engine.
        
        Args:
            db_manager: Database manager instance for logging
        """
        self.db = db_manager
        self.rules = Configuration.DETECTION_RULES
        self.alerts_generated = []
        
    def generate_simulated_logs(self, count: int = 50, include_benign: bool = True) -> List[Dict]:
        """
        Generate realistic simulated endpoint logs.
        
        This method creates a mix of benign and suspicious log entries
        to simulate real-world telemetry data. The distribution is
        designed to approximate typical enterprise environments.
        
        Args:
            count: Number of logs to generate
            include_benign: Include non-malicious activity
            
        Returns:
            List[Dict]: Generated log entries
        """
        logs = []
        
        event_types = [
            'process_create', 'network_connection', 'file_write',
            'registry_change', 'service_install', 'user_login',
            'powershell_execution', 'account_creation', 'dns_query',
            'file_read', 'service_start', 'task_schedule'
        ]
        
        suspicious_patterns = [
            'powershell -enc', 'net user /add', 'schtasks /create',
            'reg add', 'wmic process', 'certutil -urlcache',
            'rundll32', 'mshta javascript', 'bitsadmin /transfer',
            'whoami', 'ipconfig', 'netstat', 'tasklist'
        ]
        
        benign_patterns = [
            'notepad.exe', 'explorer.exe', 'svchost.exe', 'winlogon.exe',
            'services.exe', 'lsass.exe', 'wininit.exe', 'csrss.exe',
            'winlogon.exe', 'taskmgr.exe', 'calc.exe', 'cmd.exe'
        ]
        
        for i in range(count):
            timestamp = datetime.now() - timedelta(minutes=random.randint(0, 120))
            event_type = random.choice(event_types)
            
            # 25% chance of suspicious activity
            if random.random() < 0.25:
                message = f"Command: {random.choice(suspicious_patterns)} with arguments {random.randint(100, 999)}"
                source = "suspicious"
                severity = random.choice(['CRITICAL', 'HIGH', 'MEDIUM'])
            else:
                message = f"Normal system activity: {random.choice(benign_patterns)}"
                source = "normal"
                severity = "LOW"
            
            log = {
                'timestamp': timestamp.isoformat(),
                'source': source,
                'event_type': event_type,
                'message': message,
                'pid': random.randint(1000, 9999),
                'username': random.choice(['SYSTEM', 'user1', 'admin', 'user2', 'service_account']),
                'hostname': f"host-{random.randint(1, 10)}",
                'severity': severity,
                'raw_data': json.dumps({'command': message, 'user': 'user1', 'pid': random.randint(1000, 9999)})
            }
            
            logs.append(log)
            self.db.log_event(log)
        
        return logs
    
    def analyze_logs(self, logs: List[Dict]) -> List[Dict]:
        """
        Analyze logs against detection rules.
        
        This method applies the detection rule set to the provided
        logs and generates alerts for matching events.
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List[Dict]: Generated alerts
        """
        alerts = []
        
        for log in logs:
            for rule_key, rule in self.rules.items():
                if self._matches_rule(log, rule_key):
                    alert = {
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'description': rule['description'],
                        'mitre_technique': rule.get('mitre_technique', ''),
                        'tactic': rule.get('tactic', ''),
                        'source_events': [log],
                        'timestamp': log['timestamp'],
                        'risk_score': self._calculate_risk_score(rule['severity']),
                        'confidence_score': self._calculate_confidence_score(log, rule),
                        'status': 'NEW',
                        'containment_status': 'PENDING'
                    }
                    alerts.append(alert)
                    
                    alert_id = self.db.create_alert(alert)
                    alert['alert_id'] = alert_id
        
        self.alerts_generated.extend(alerts)
        return alerts
    
    def _matches_rule(self, log: Dict, rule_key: str) -> bool:
        """
        Determine if a log matches a detection rule.
        
        Args:
            log: Log entry to evaluate
            rule_key: Rule identifier
            
        Returns:
            bool: True if the log matches the rule
        """
        message = log.get('message', '').lower()
        source = log.get('source', '')
        event_type = log.get('event_type', '')
        
        rule_patterns = {
            'powershell_abuse': ['powershell -enc', 'powershell -e', 'powershell -c'],
            'local_account_creation': ['net user /add', 'useradd', 'new-localuser'],
            'privilege_escalation': ['privilege', 'elevate', 'admin bypass'],
            'persistence_mechanism': ['schtasks /create', 'reg add', 'startup'],
            'lateral_movement': ['wmic process', 'psexec', 'net use'],
            'data_exfiltration': ['certutil -urlcache', 'bitsadmin', 'upload'],
            'credential_dumping': ['mimikatz', 'secretsdump', 'lsadump'],
            'command_and_control': ['c2', 'callback', 'beacon', 'http post'],
            'defense_evasion': ['disable', 'stop service', 'kill', 'delete'],
            'discovery': ['whoami', 'ipconfig', 'netstat', 'tasklist']
        }
        
        patterns = rule_patterns.get(rule_key, [])
        
        for pattern in patterns:
            if pattern in message:
                return True
        
        if source == 'suspicious':
            return True
        
        return False
    
    def _calculate_risk_score(self, severity: str) -> float:
        """
        Calculate a numeric risk score based on severity.
        
        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            
        Returns:
            float: Risk score between 0 and 10
        """
        base_scores = {
            'CRITICAL': 8.5,
            'HIGH': 7.0,
            'MEDIUM': 5.0,
            'LOW': 3.0
        }
        base_score = base_scores.get(severity, 5.0)
        return min(10.0, base_score + random.uniform(-0.5, 0.5))
    
    def _calculate_confidence_score(self, log: Dict, rule: Dict) -> float:
        """
        Calculate confidence in a detection.
        
        Args:
            log: Log entry
            rule: Detection rule
            
        Returns:
            float: Confidence score between 0 and 1
        """
        base_confidence = {
            'CRITICAL': 0.85,
            'HIGH': 0.75,
            'MEDIUM': 0.60,
            'LOW': 0.45
        }
        
        confidence = base_confidence.get(rule.get('severity', 'MEDIUM'), 0.60)
        
        if log.get('source') == 'suspicious':
            confidence += 0.1
        
        return round(max(0, min(1.0, confidence)), 2)


# ============================================================================
# Alert Engine
# ============================================================================

class AlertEngine:
    """
    Alerting layer of the threat response pipeline.
    
    This engine processes raw alerts, adds correlation information,
    and manages notification delivery. It simulates integration with
    collaboration platforms to provide real-time visibility.
    
    Key Capabilities:
        - Alert correlation and deduplication
        - Severity-based escalation
        - Notification delivery simulation
        - Alert enrichment with context
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize the alert engine.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
        self.alerts = []
    
    def process_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """
        Process and correlate incoming alerts.
        
        Args:
            alerts: Raw alerts from detection engine
            
        Returns:
            List[Dict]: Processed alerts with correlation data
        """
        processed_alerts = []
        
        for alert in alerts:
            correlation_id = hashlib.md5(
                f"{alert['rule_name']}{alert['timestamp']}".encode()
            ).hexdigest()[:8]
            alert['correlation_id'] = correlation_id
            
            alert['confidence_score'] = alert.get('confidence_score', 0.60)
            
            alert_id = self.db.create_alert(alert)
            alert['alert_id'] = alert_id
            
            processed_alerts.append(alert)
        
        self.alerts.extend(processed_alerts)
        return processed_alerts
    
    def send_slack_notification(self, alert: Dict) -> Dict:
        """
        Simulate sending a Slack notification.
        
        Args:
            alert: Alert data
            
        Returns:
            Dict: Notification result
        """
        severity_emoji = {
            'CRITICAL': 'Critical',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low'
        }
        emoji = severity_emoji.get(alert.get('severity', 'MEDIUM'), 'Information')
        
        notification = {
            'webhook_url': Configuration.SLACK_WEBHOOK_URL,
            'payload': {
                'text': f"Alert: {alert.get('rule_name', 'Unknown Rule')}",
                'attachments': [
                    {
                        'color': alert.get('severity', 'MEDIUM').lower(),
                        'fields': [
                            {'title': 'Severity', 'value': alert.get('severity', 'UNKNOWN'), 'short': True},
                            {'title': 'Description', 'value': alert.get('description', ''), 'short': True},
                            {'title': 'Risk Score', 'value': str(alert.get('risk_score', 0.0)), 'short': True},
                            {'title': 'MITRE Technique', 'value': alert.get('mitre_technique', 'N/A'), 'short': True}
                        ],
                        'footer': 'Threat Response Pipeline'
                    }
                ]
            },
            'sent_at': datetime.now().isoformat(),
            'status': 'DELIVERED'
        }
        
        self.db.log_response_action(
            alert.get('alert_id', 'unknown'),
            'slack_notification',
            'SENT',
            {'webhook': Configuration.SLACK_WEBHOOK_URL, 'alert': alert.get('rule_name')}
        )
        
        return notification
    
    def send_siem_notification(self, alert: Dict) -> Dict:
        """
        Simulate sending to SIEM (Splunk HEC).
        
        Args:
            alert: Alert data
            
        Returns:
            Dict: SIEM ingestion result
        """
        siem_event = {
            'time': datetime.now().timestamp(),
            'host': 'threat-response-pipeline',
            'source': 'detection_engine',
            'sourcetype': 'threat_pipeline_alerts',
            'event': alert
        }
        
        result = {
            'endpoint': Configuration.SPLUNK_HEC_URL,
            'payload': siem_event,
            'sent_at': datetime.now().isoformat(),
            'status': 'DELIVERED'
        }
        
        self.db.log_response_action(
            alert.get('alert_id', 'unknown'),
            'siem_forwarding',
            'SENT',
            {'siem': 'splunk', 'alert': alert.get('rule_name')}
        )
        
        return result
    
    def escalate_critical(self, alert: Dict) -> Dict:
        """
        Escalate critical alerts for human review.
        
        Args:
            alert: Alert data
            
        Returns:
            Dict: Escalation result
        """
        escalation = {
            'alert_id': alert.get('alert_id', 'unknown'),
            'escalation_level': 'SOC_TIER2',
            'reason': 'Critical severity alert requires human review',
            'timestamp': datetime.now().isoformat(),
            'status': 'ESCALATED'
        }
        
        self.db.log_response_action(
            alert.get('alert_id', 'unknown'),
            'escalate_critical',
            'ESCALATED',
            {'tier': 'SOC_TIER2', 'reason': alert.get('description', '')}
        )
        
        return escalation


# ============================================================================
# Enrichment Engine
# ============================================================================

class EnrichmentEngine:
    """
    Enrichment layer of the threat response pipeline.
    
    This engine augments alerts with contextual threat intelligence
    from multiple sources. It implements caching to optimize performance
    and reduce redundant lookups.
    
    Key Capabilities:
        - Threat intelligence lookup (VirusTotal simulation)
        - Caching for performance optimization
        - Contextual enrichment with reputation data
        - Confidence scoring based on enrichment results
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize the enrichment engine.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
        self.enrichment_cache = {}
    
    def enrich_alert(self, alert: Dict) -> Dict:
        """
        Enrich an alert with threat intelligence.
        
        Args:
            alert: Alert data
            
        Returns:
            Dict: Enriched alert
        """
        indicator = hashlib.md5(
            f"{alert.get('rule_name')}{alert.get('timestamp')}".encode()
        ).hexdigest()
        
        cached = self.db.get_cached_intel(indicator)
        if cached:
            alert['enriched_data'] = cached['details']
            alert['verdict'] = cached['verdict']
            return alert
        
        verdicts = ['malicious', 'suspicious', 'clean', 'unknown']
        weights = [0.15, 0.25, 0.35, 0.25]
        
        if alert.get('severity') == 'CRITICAL':
            weights = [0.35, 0.30, 0.20, 0.15]
        elif alert.get('severity') == 'HIGH':
            weights = [0.25, 0.30, 0.25, 0.20]
        
        verdict = random.choices(verdicts, weights=weights)[0]
        
        enrichment = {
            'virustotal': {
                'verdict': verdict,
                'positives': random.randint(0, 50) if verdict in ['malicious', 'suspicious'] else random.randint(0, 5),
                'total_scans': random.randint(60, 75),
                'scan_date': datetime.now().isoformat(),
                'permalink': f"https://www.virustotal.com/gui/file/{indicator}"
            },
            'reputation': {
                'threat_score': random.randint(0, 100),
                'reputation_context': 'notable' if verdict in ['malicious', 'suspicious'] else 'clean',
                'community': random.choice(['active', 'moderate', 'limited'])
            },
            'additional_context': {
                'submissions': random.randint(0, 100),
                'last_seen': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat(),
                'related_indicators': [hashlib.md5(str(random.randint(1, 1000)).encode()).hexdigest()[:8] for _ in range(random.randint(2, 5))]
            }
        }
        
        alert['enriched_data'] = enrichment
        alert['verdict'] = verdict
        
        if verdict in ['malicious', 'suspicious']:
            alert['risk_score'] = min(10.0, alert.get('risk_score', 5.0) + 2.0)
            alert['confidence_score'] = min(1.0, alert.get('confidence_score', 0.6) + 0.15)
        
        self.db.cache_threat_intel(indicator, verdict, enrichment)
        
        return alert
    
    def bulk_enrich(self, alerts: List[Dict]) -> List[Dict]:
        """
        Enrich multiple alerts.
        
        Args:
            alerts: List of alerts            
        Returns:
            List[Dict]: Enriched alerts
        """
        enriched = []
        for alert in alerts:
            enriched.append(self.enrich_alert(alert))
        return enriched


# ============================================================================
# Response Engine
# ============================================================================

class ResponseEngine:
    """
    Response layer of the threat response pipeline.
    
    This engine evaluates alerts and executes appropriate response
    actions based on risk score and severity. It implements a
    graduated response model:
    
        1. Critical/High Risk: Auto-containment via MDM
        2. Medium Risk: Escalation for review
        3. Low Risk: Logging and monitoring
    
    Key Capabilities:
        - Risk-based action selection
        - Automated containment simulation
        - Escalation workflows
        - Audit trail of all actions
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize the response engine.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
        self.response_actions = []
    
    def evaluate_response(self, alert: Dict) -> Dict:
        """
        Evaluate and execute response actions.
        
        Args:
            alert: Alert data
            
        Returns:
            Dict: Response result
        """
        response = {
            'alert_id': alert.get('alert_id', 'unknown'),
            'actions': [],
            'containment_status': 'PENDING'
        }
        
        risk_score = alert.get('risk_score', 0.0)
        severity = alert.get('severity', 'MEDIUM')
        
        if risk_score >= Configuration.AUTO_CONTAINMENT_THRESHOLD or severity == 'CRITICAL':
            response['actions'].append(self._auto_contain(alert))
            response['containment_status'] = 'CONTAINED'
        elif risk_score >= Configuration.ESCALATION_THRESHOLD or severity == 'HIGH':
            response['actions'].append(self._escalate(alert))
            response['containment_status'] = 'ESCALATED'
        else:
            response['actions'].append(self._monitor(alert))
            response['containment_status'] = 'MONITORING'
        
        for action in response['actions']:
            self.db.log_response_action(
                alert.get('alert_id', 'unknown'),
                action['action'],
                action['status'],
                action['details']
            )
        
        self.db.record_metric('response_time', random.uniform(0.5, 5.0), {'alert_id': alert.get('alert_id')})
        
        return response
    
    def _auto_contain(self, alert: Dict) -> Dict:
        """
        Execute automated containment via MDM.
        
        Args:
            alert: Alert data
            
        Returns:
            Dict: Containment result
        """
        device_id = f"device-{random.randint(1000, 9999)}"
        
        response = {
            'action': 'AUTO_CONTAIN',
            'status': 'SUCCESS',
            'details': {
                'device_id': device_id,
                'action_taken': 'Quarantined device',
                'mdm_endpoint': Configuration.MDM_API_ENDPOINT,
                'timestamp': datetime.now().isoformat(),
                'containment_reason': alert.get('description', ''),
                'alert_rule': alert.get('rule_name', '')
            }
        }
        return response
    
    def _escalate(self, alert: Dict) -> Dict:
        """
        Escalate for human review.
        
        Args:
            alert: Alert data
            
        Returns:
            Dict: Escalation result
        """
        tier_options = ['SOC_TIER1', 'SOC_TIER2', 'IR_TEAM']
        tier = random.choice(tier_options)
        
        return {
            'action': 'ESCALATE',
            'status': 'PENDING_REVIEW',
            'details': {
                'reason': 'Alert requires human investigation',
                'escalation_team': tier,
                'severity': alert.get('severity', 'UNKNOWN'),
                'risk_score': alert.get('risk_score', 0.0),
                'alert_description': alert.get('description', '')
            }
        }
    
    def _monitor(self, alert: Dict) -> Dict:
        """
        Log and monitor without immediate action.
        
        Args:
            alert: Alert data
            
        Returns:
            Dict: Monitoring result
        """
        return {
            'action': 'MONITOR',
            'status': 'LOGGED',
            'details': {
                'reason': 'Low to medium severity alert, monitoring only',
                'alert_id': alert.get('alert_id', 'unknown'),
                'monitoring_duration': '24 hours',
                'threshold_for_escalation': Configuration.ESCALATION_THRESHOLD
            }
        }
    
    def get_response_summary(self) -> Dict:
        """
        Generate summary of response actions.
        
        Returns:
            Dict: Response summary statistics
        """
        stats = {
            'total_actions': len(self.response_actions),
            'containments': 0,
            'escalations': 0,
            'monitoring': 0,
            'average_response_time': 0.0
        }
        
        for action in self.response_actions:
            action_type = action.get('action', '')
            if 'CONTAIN' in action_type:
                stats['containments'] += 1
            elif 'ESCALATE' in action_type:
                stats['escalations'] += 1
            else:
                stats['monitoring'] += 1
        
        return stats


# ============================================================================
# Reporting Engine
# ============================================================================

class ReportingEngine:
    """
    Reporting layer of the threat response pipeline.
    
    This engine generates comprehensive reports in multiple formats
    suitable for different audiences and use cases.
    
    Key Capabilities:
        - Console reports for operational visibility
        - HTML reports for management consumption
        - CSV exports for compliance and analysis
        - JSON exports for SIEM integration
        - Executive summaries with key metrics
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize the reporting engine.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
        self.timestamp = datetime.now()
    
    def generate_console_report(self, stats: Dict, alerts: List[Dict]) -> str:
        """
        Generate a formatted console report.
        
        Args:
            stats: Pipeline statistics
            alerts: Recent alerts
            
        Returns:
            str: Formatted report
        """
        report = []
        report.append("")
        report.append("=" * 80)
        report.append("THREAT RESPONSE PIPELINE - OPERATIONAL REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("-" * 80)
        
        report.append("")
        report.append("Pipeline Statistics:")
        report.append(f"  Total Events Processed: {stats.get('total_events', 0):,}")
        report.append(f"  Total Alerts Generated: {stats.get('total_alerts', 0):,}")
        report.append(f"  Average Risk Score: {stats.get('average_risk_score', 0.0):.2f}")
        report.append(f"  Average Confidence: {stats.get('average_confidence', 0.0):.2f}")
        
        report.append("")
        report.append("Severity Distribution:")
        for severity, count in stats.get('severity_distribution', {}).items():
            report.append(f"  {severity}: {count}")
        
        report.append("")
        report.append("Containment Status:")
        for status, count in stats.get('containment_status', {}).items():
            report.append(f"  {status}: {count}")
        
        report.append("")
        report.append("Recent Alerts:")
        for alert in alerts[:5]:
            report.append(f"  [{alert.get('severity', 'UNKNOWN')}] {alert.get('rule_name', 'Unknown Rule')}")
            report.append(f"    Risk Score: {alert.get('risk_score', 0.0):.2f}")
            report.append(f"    Status: {alert.get('containment_status', 'PENDING')}")
            report.append(f"    MITRE: {alert.get('mitre_technique', 'N/A')}")
            report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def generate_html_report(self, stats: Dict, alerts: List[Dict]) -> str:
        """
        Generate a professional HTML report.
        
        Args:
            stats: Pipeline statistics
            alerts: Recent alerts
            
        Returns:
            str: HTML content
        """
        timestamp = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Threat Response Pipeline - Status Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a1a; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #12122a; border-radius: 8px; padding: 30px; border: 1px solid #2a2a4a; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 15px; font-weight: 300; }}
        h2 {{ color: #00d4ff; margin-top: 25px; font-weight: 300; }}
        .header-info {{ display: flex; gap: 30px; margin: 20px 0; padding: 15px; background: #1a1a3a; border-radius: 4px; flex-wrap: wrap; }}
        .header-info div {{ font-size: 14px; }}
        .header-info strong {{ color: #00d4ff; }}
        
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #1a1a3a; padding: 20px; border-radius: 6px; text-align: center; border: 1px solid #2a2a4a; }}
        .stat-card .number {{ font-size: 36px; font-weight: bold; color: #00d4ff; }}
        .stat-card .label {{ font-size: 12px; color: #8888aa; margin-top: 5px; }}
        
        .alert {{ padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #444; background: #1a1a3a; }}
        .alert-CRITICAL {{ border-left-color: #ff0040; background: #2a0a1a; }}
        .alert-HIGH {{ border-left-color: #ff6600; background: #2a1a0a; }}
        .alert-MEDIUM {{ border-left-color: #ffcc00; background: #2a2a0a; }}
        .alert-LOW {{ border-left-color: #00cc66; background: #0a2a1a; }}
        .alert-title {{ font-weight: bold; color: #ffffff; }}
        .alert-meta {{ font-size: 12px; color: #8888aa; margin-top: 5px; }}
        
        .status-badge {{ display: inline-block; padding: 3px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        .status-CONTAINED {{ background: #00cc66; color: #000; }}
        .status-ESCALATED {{ background: #ff6600; color: #000; }}
        .status-MONITORING {{ background: #ffcc00; color: #000; }}
        .status-PENDING {{ background: #888; color: #000; }}
        
        .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #2a2a4a; font-size: 12px; color: #666688; text-align: center; }}
        
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; background: #2a2a4a; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Threat Response Pipeline</h1>
        <p style="color: #8888aa;">Enterprise Security Operations Automation</p>
        
        <div class="header-info">
            <div><strong>Report Generated:</strong> {timestamp}</div>
            <div><strong>Total Events:</strong> {stats.get('total_events', 0):,}</div>
            <div><strong>Total Alerts:</strong> {stats.get('total_alerts', 0):,}</div>
            <div><strong>Avg Risk Score:</strong> {stats.get('average_risk_score', 0.0):.2f}</div>
        </div>
        
        <h2>Pipeline Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{stats.get('total_events', 0):,}</div>
                <div class="label">Events Processed</div>
            </div>
            <div class="stat-card">
                <div class="number">{stats.get('total_alerts', 0):,}</div>
                <div class="label">Alerts Generated</div>
            </div>
            <div class="stat-card">
                <div class="number">{stats.get('average_risk_score', 0.0):.2f}</div>
                <div class="label">Avg Risk Score</div>
            </div>
            <div class="stat-card">
                <div class="number">{stats.get('average_confidence', 0.0):.2f}</div>
                <div class="label">Avg Confidence</div>
            </div>
        </div>
        
        <h2>Recent Alerts</h2>
"""
        
        for alert in alerts[:10]:
            severity = alert.get('severity', 'MEDIUM')
            status = alert.get('containment_status', 'PENDING')
            html += f"""
        <div class="alert alert-{severity}">
            <div class="alert-title">[{severity}] {alert.get('rule_name', 'Unknown Rule')}</div>
            <div>{alert.get('description', '')}</div>
            <div class="alert-meta">
                Risk Score: {alert.get('risk_score', 0.0):.2f} | 
                MITRE: {alert.get('mitre_technique', 'N/A')} | 
                Confidence: {alert.get('confidence_score', 0.0):.2f} |
                Status: <span class="status-badge status-{status}">{status}</span>
            </div>
        </div>
"""
        
        html += f"""
        <div class="footer">
            Generated by Threat Response Pipeline v2.0.0<br>
            Detection → Alerting → Enrichment → Response → Logging → Reporting
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def generate_executive_summary(self, stats: Dict) -> str:
        """
        Generate an executive summary report.
        
        Args:
            stats: Pipeline statistics
            
        Returns:
            str: Executive summary
        """
        summary = []
        summary.append("THREAT RESPONSE PIPELINE - EXECUTIVE SUMMARY")
        summary.append("=" * 60)
        summary.append("")
        summary.append(f"Reporting Period: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append("")
        summary.append("Key Metrics:")
        summary.append(f"  Total Events: {stats.get('total_events', 0):,}")
        summary.append(f"  Alerts Generated: {stats.get('total_alerts', 0):,}")
        summary.append(f"  Average Risk Score: {stats.get('average_risk_score', 0.0):.2f}")
        summary.append("")
        summary.append("Risk Distribution:")
        
        for severity, count in stats.get('severity_distribution', {}).items():
            percentage = (count / max(stats.get('total_alerts', 1), 1)) * 100
            summary.append(f"  {severity}: {count} ({percentage:.1f}%)")
        
        summary.append("")
        summary.append("Containment Status:")
        for status, count in stats.get('containment_status', {}).items():
            percentage = (count / max(stats.get('total_alerts', 1), 1)) * 100
            summary.append(f"  {status}: {count} ({percentage:.1f}%)")
        
        summary.append("")
        summary.append("Recommendations:")
        if stats.get('average_risk_score', 0.0) > 6.0:
            summary.append("  - High average risk score detected. Review detection rules.")
        
        critical_count = stats.get('severity_distribution', {}).get('CRITICAL', 0)
        if critical_count > 0:
            summary.append("  - Critical alerts present. Immediate investigation required.")
        
        summary.append("  - Continue monitoring and tuning detection rules.")
        summary.append("")
        summary.append("=" * 60)
        
        return "\n".join(summary)
    
    def generate_csv_report(self, alerts: List[Dict]) -> str:
        """
        Generate CSV export for compliance or analysis.
        
        Args:
            alerts: List of alerts
            
        Returns:
            str: CSV content
        """
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        fields = [
            'alert_id', 'timestamp', 'rule_name', 'severity',
            'description', 'risk_score', 'containment_status',
            'mitre_technique', 'tactic', 'confidence_score'
        ]
        writer.writerow(fields)
        
        for alert in alerts:
            row = [str(alert.get(f, '')) for f in fields]
            writer.writerow(row)
        
        return output.getvalue()
    
    def generate_json_report(self, stats: Dict, alerts: List[Dict]) -> str:
        """
        Generate JSON export for SIEM integration.
        
        Args:
            stats: Pipeline statistics
            alerts: List of alerts
            
        Returns:
            str: JSON content
        """
        report = {
            'report_timestamp': self.timestamp.isoformat(),
            'statistics': stats,
            'alerts': alerts[:50]
        }
        return json.dumps(report, indent=2)


# ============================================================================
# Pipeline Orchestrator
# ============================================================================

class ThreatResponsePipeline:
    """
    Main orchestrator for the unified threat response pipeline.
    
    This class coordinates all six layers of the pipeline and provides
    a unified interface for execution and reporting.
    
    Layers:
        1. Detection: Log ingestion and analysis
        2. Alerting: Alert generation and notification
        3. Enrichment: Threat intelligence enrichment
        4. Response: Automated response execution
        5. Logging: Audit trail and metrics
        6. Reporting: Comprehensive reporting
    """
    
    def __init__(self):
        """
        Initialize the pipeline with all components.
        """
        self.db = DatabaseManager()
        self.detection = DetectionEngine(self.db)
        self.alerting = AlertEngine(self.db)
        self.enrichment = EnrichmentEngine(self.db)
        self.response = ResponseEngine(self.db)
        self.reporting = ReportingEngine(self.db)
    
    def run_once(self, event_count: int = 50) -> Dict:
        """
        Execute one complete pipeline cycle.
        
        Args:
            event_count: Number of logs to generate
            
        Returns:
            Dict: Pipeline results
        """
        print("")
        print("=" * 80)
        print("THREAT RESPONSE PIPELINE - EXECUTING CYCLE")
        print("=" * 80)
        
        logs = self.detection.generate_simulated_logs(count=event_count)
        print(f"\n[Detection] Generated {len(logs)} events")
        
        alerts = self.detection.analyze_logs(logs)
        print(f"[Detection] Generated {len(alerts)} raw alerts")
        
        processed_alerts = self.alerting.process_alerts(alerts)
        print(f"[Alerting] Processed {len(processed_alerts)} alerts")
        
        enriched_alerts = self.enrichment.bulk_enrich(processed_alerts)
        print(f"[Enrichment] Enriched {len(enriched_alerts)} alerts")
        
        for alert in enriched_alerts[:3]:
            self.response.evaluate_response(alert)
        
        print(f"[Response] Executed response actions for {min(3, len(enriched_alerts))} alerts")
        
        self.db.record_metric('pipeline_execution_time', random.uniform(0.5, 2.0))
        
        return {
            'logs_generated': len(logs),
            'alerts_generated': len(alerts),
            'alerts_processed': len(processed_alerts),
            'alerts_enriched': len(enriched_alerts),
            'responses_executed': min(3, len(enriched_alerts))
        }
    
    def generate_reports(self) -> Dict:
        """
        Generate all reports.
        
        Returns:
            Dict: Report file paths
        """
        os.makedirs(Configuration.OUTPUT_DIR, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        stats = self.db.get_statistics()
        alerts = self.db.get_alerts(limit=25)
        
        results = {}
        
        html_content = self.reporting.generate_html_report(stats, alerts)
        html_file = f"{Configuration.OUTPUT_DIR}/pipeline_report_{timestamp}.html"
        with open(html_file, 'w') as f:
            f.write(html_content)
        results['html_report'] = html_file
        
        csv_content = self.reporting.generate_csv_report(alerts)
        csv_file = f"{Configuration.OUTPUT_DIR}/pipeline_report_{timestamp}.csv"
        with open(csv_file, 'w') as f:
            f.write(csv_content)
        results['csv_report'] = csv_file
        
        json_content = self.reporting.generate_json_report(stats, alerts)
        json_file = f"{Configuration.OUTPUT_DIR}/pipeline_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            f.write(json_content)
        results['json_report'] = json_file
        
        console_report = self.reporting.generate_console_report(stats, alerts)
        print(console_report)
        
        summary = self.reporting.generate_executive_summary(stats)
        print(summary)
        
        return results


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """
    Main entry point for the threat response pipeline.
    """
    print("")
    print("=" * 80)
    print("UNIFIED THREAT RESPONSE PIPELINE")
    print("=" * 80)
    print("Enterprise Security Operations Automation")
    print("-" * 80)
    
    pipeline = ThreatResponsePipeline()
    
    while True:
        print("")
        print("Options:")
        print("  1. Run Pipeline Cycle")
        print("  2. Generate Reports")
        print("  3. View Statistics")
        print("  4. Export for SIEM")
        print("  5. Run Demo (5 cycles)")
        print("  6. Exit")
        
        choice = input("\nSelect an option: ").strip()
        
        if choice == '1':
            count = input("Number of events to generate (default 50): ").strip()
            count = int(count) if count.isdigit() else 50
            result = pipeline.run_once(event_count=count)
            print(f"\nPipeline complete: {result}")
            
        elif choice == '2':
            results = pipeline.generate_reports()
            print("\nReports generated:")
            for report_type, path in results.items():
                print(f"  {report_type}: {path}")
            
        elif choice == '3':
            stats = pipeline.db.get_statistics()
            print("\nPipeline Statistics:")
            print(f"  Total Events: {stats.get('total_events', 0):,}")
            print(f"  Total Alerts: {stats.get('total_alerts', 0):,}")
            print(f"  Average Risk Score: {stats.get('average_risk_score', 0.0):.2f}")
            print(f"  Average Confidence: {stats.get('average_confidence', 0.0):.2f}")
            print("  Severity Distribution:")
            for severity, count in stats.get('severity_distribution', {}).items():
                print(f"    {severity}: {count}")
            
        elif choice == '4':
            print("\nExport Formats:")
            print("  1. JSON")
            print("  2. CSV")
            fmt_choice = input("Select format: ").strip()
            fmt = 'json' if fmt_choice == '1' else 'csv'
            limit = input("Number of alerts to export (default 100): ").strip()
            limit = int(limit) if limit.isdigit() else 100
            
            export_data = pipeline.db.export_for_siem(fmt, limit)
            filename = f"{Configuration.OUTPUT_DIR}/siem_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
            
            os.makedirs(Configuration.OUTPUT_DIR, exist_ok=True)
            with open(filename, 'w') as f:
                f.write(export_data)
            print(f"\nExport saved to: {filename}")
            
        elif choice == '5':
            print("\nRunning 5 pipeline cycles...")
            for i in range(5):
                print(f"\nCycle {i+1}/5")
                pipeline.run_once(event_count=40)
            
            results = pipeline.generate_reports()
            print("\nReports generated:")
            for report_type, path in results.items():
                print(f"  {report_type}: {path}")
            
        elif choice == '6':
            print("\nExiting Threat Response Pipeline.")
            break
            
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()