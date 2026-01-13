"""
🚀 ACCURATE CYBER DEFENSE ULTIMATE CYBERSECURITY TOOLKIT PRO - Enhanced Edition v0.0.1
Author: Ian Carter Kulani
Version: 0.0.1
Features:
- Network Monitoring & Threat Detection
- Advanced Scanning & Reconnaissance
- Complete Telegram Bot Integration with 300+ Commands
- Database Logging & Reporting
- Red Themed CLI Interface
- Enhanced Traceroute Tools
- DDoS Detection & Prevention
- Real-time Alerts & Notifications
- Command Templates & Automation
- Traffic Generation & Load Testing
- System & Network Information
- Complete Information Gathering Suite
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import hashlib
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from colorama import init, Fore, Style, Back
import shutil
import uuid
import base64
import csv
import getpass

# Initialize colorama
init(autoreset=True)

# ============================
# CONFIGURATION
# ============================
CONFIG_FILE = "cybertool_config.json"
TELEGRAM_CONFIG_FILE = "telegram_config.json"
LOG_FILE = "cybertool.log"
DATABASE_FILE = "cybertool.db"
REPORT_DIR = "reports"
COMMAND_HISTORY_FILE = "command_history.json"
TEMPLATES_DIR = "templates"
SCANS_DIR = "scans"
ALERTS_DIR = "alerts"

# Create directories
for directory in [REPORT_DIR, TEMPLATES_DIR, SCANS_DIR, ALERTS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("CyberTool")

# ============================
# DATA CLASSES
# ============================
@dataclass
class ThreatAlert:
    """Threat alert data class"""
    id: str
    timestamp: str
    threat_type: str
    source_ip: str
    target_ip: str
    severity: str
    description: str
    action_taken: str
    resolved: bool

@dataclass
class ScanResult:
    """Scan result data class"""
    id: str
    timestamp: str
    target: str
    scan_type: str
    ports: List[int]
    services: Dict
    vulnerabilities: List[str]
    risk_level: str

@dataclass
class NetworkConnection:
    """Network connection data class"""
    timestamp: str
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    process_name: str
    process_id: int

# ============================
# ENHANCED TRACEROUTE TOOL
# ============================
class TracerouteTool:
    """Enhanced interactive traceroute tool with geolocation and visualization"""
    
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.geolocation_cache = {}
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))
    
    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()
        
        if system == 'Windows':
            return ['tracert', '-d', target]
        
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', '-m', '30', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]
        
        raise EnvironmentError('No traceroute utilities found on this system.')
    
    def get_geolocation(self, ip: str) -> Dict:
        """Get geolocation for IP address"""
        if ip in self.geolocation_cache:
            return self.geolocation_cache[ip]
        
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    self.geolocation_cache[ip] = data
                    return data
        except:
            pass
        
        return {
            'country': 'Unknown',
            'regionName': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown',
            'lat': 0,
            'lon': 0
        }
    
    def stream_subprocess(self, cmd: List[str]) -> Tuple[int, str, List[Dict]]:
        """Run subprocess and capture output with hop analysis"""
        output_lines = []
        hops = []
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            
            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    
                    # Parse traceroute output for hops
                    hop_match = re.match(r'\s*(\d+)\s+([\d\.]+|[\w:]+)\s+', cleaned_line)
                    if hop_match:
                        hop_num = int(hop_match.group(1))
                        hop_ip = hop_match.group(2)
                        
                        if self.is_ipv4_or_ipv6(hop_ip):
                            geo = self.get_geolocation(hop_ip)
                            hops.append({
                                'hop': hop_num,
                                'ip': hop_ip,
                                'country': geo.get('country', 'Unknown'),
                                'isp': geo.get('isp', 'Unknown'),
                                'latency': self._extract_latency(cleaned_line)
                            })
                    
                    print(cleaned_line)
            
            proc.wait()
            return proc.returncode, '\n'.join(output_lines), hops
            
        except KeyboardInterrupt:
            print('\n[+] User cancelled. Terminating traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines), hops
        except Exception as e:
            error_msg = f'[!] Error running command: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines), hops
    
    def _extract_latency(self, line: str) -> str:
        """Extract latency from traceroute output"""
        patterns = [
            r'(\d+\.\d+)\s*ms',
            r'(\d+)\s*ms',
            r'<\d+\s*ms',
            r'\*\s*\*\s*\*'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        
        return "N/A"
    
    def interactive_traceroute(self, target: str = None, advanced: bool = False) -> str:
        """Run interactive traceroute with enhanced features"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."
        
        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"
        
        try:
            if advanced:
                cmd = self._choose_advanced_traceroute(target)
            else:
                cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"
        
        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output, hops = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time
        
        # Generate enhanced report
        result = self._generate_enhanced_report(target, cmd, output, execution_time, returncode, hops)
        
        return result
    
    def _choose_advanced_traceroute(self, target: str) -> List[str]:
        """Choose advanced traceroute command based on available tools"""
        if platform.system() == 'Windows':
            return ['tracert', '-d', '-h', '30', '-w', '1000', target]
        
        if shutil.which('mtr'):
            return ['mtr', '--report', '--report-wide', '--no-dns', target]
        elif shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '3', '-w', '3', '-m', '40', '-z', '100', target]
        else:
            return self.choose_traceroute_cmd(target)
    
    def _generate_enhanced_report(self, target: str, cmd: List[str], output: str, 
                                 execution_time: float, returncode: int, 
                                 hops: List[Dict]) -> str:
        """Generate enhanced traceroute report"""
        result = f"🚀 <b>ENHANCED TRACEROUTE REPORT</b>\n\n"
        result += f"📌 Target: <code>{target}</code>\n"
        result += f"🔧 Command: <code>{' '.join(cmd)}</code>\n"
        result += f"⏱️ Execution Time: {execution_time:.2f}s\n"
        result += f"📊 Return Code: {returncode}\n\n"
        
        if hops:
            result += f"🌍 <b>GEOGRAPHICAL ANALYSIS</b>\n"
            result += f"Hops: {len(hops)}\n\n"
            
            # Group by country
            countries = {}
            for hop in hops:
                country = hop['country']
                if country not in countries:
                    countries[country] = []
                countries[country].append(hop)
            
            for country, country_hops in countries.items():
                result += f"📍 {country}: {len(country_hops)} hops\n"
            
            result += "\n"
            
            # Show first 10 hops with details
            result += f"🛣️ <b>FIRST 10 HOPS</b>\n"
            for hop in hops[:10]:
                result += f"{hop['hop']:2d}. {hop['ip']:15s} | {hop['country']:15s} | {hop['latency']}\n"
            
            if len(hops) > 10:
                result += f"... and {len(hops) - 10} more hops\n\n"
        
        # Add raw output (limited)
        if len(output) > 2000:
            result += f"📄 <b>RAW OUTPUT (LAST 2000 CHARS)</b>\n<code>{output[-2000:]}</code>"
        else:
            result += f"📄 <b>RAW OUTPUT</b>\n<code>{output}</code>"
        
        return result
    
    def prompt_target(self) -> Optional[str]:
        """Prompt user for target"""
        while True:
            user_input = input('Enter target IP address or hostname to traceroute (or type "quit" to exit): ').strip()
            if not user_input:
                print('Please enter a non-empty value.')
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                return None
            
            if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                return user_input
            else:
                print('Invalid IP address or hostname. Examples: 8.8.8.8, 2001:4860:4860::8888, example.com')

# ============================
# DATABASE MANAGER
# ============================
class DatabaseManager:
    """Enhanced database manager for comprehensive logging"""
    
    def __init__(self):
        self.conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize all database tables"""
        tables = [
            # Threats table
            '''
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                target_ip TEXT,
                severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0,
                resolved_at DATETIME,
                metadata TEXT
            )
            ''',
            # Commands history
            '''
            CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL,
                user TEXT
            )
            ''',
            # Scan results
            '''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                ports TEXT,
                services TEXT,
                vulnerabilities TEXT,
                risk_level TEXT,
                raw_output TEXT,
                duration REAL
            )
            ''',
            # Network connections
            '''
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                protocol TEXT,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                status TEXT,
                process_name TEXT,
                process_id INTEGER,
                country TEXT,
                asn TEXT
            )
            ''',
            # Traceroute results
            '''
            CREATE TABLE IF NOT EXISTS traceroute_results (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                hops INTEGER,
                success BOOLEAN DEFAULT 1
            )
            ''',
            # Monitored IPs
            '''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id TEXT PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                notes TEXT,
                tags TEXT
            )
            ''',
            # Command templates
            '''
            CREATE TABLE IF NOT EXISTS command_templates (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                command TEXT NOT NULL,
                description TEXT,
                parameters TEXT,
                usage_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''',
            # System metrics
            '''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent REAL,
                network_recv REAL,
                connections_count INTEGER,
                processes_count INTEGER
            )
            '''
        ]
        
        for table_sql in tables:
            try:
                self.cursor.execute(table_sql)
            except Exception as e:
                logger.error(f"Error creating table: {e}")
        
        self.conn.commit()
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat to database"""
        try:
            self.cursor.execute('''
                INSERT INTO threats 
                (id, timestamp, threat_type, source_ip, target_ip, severity, description, action_taken, resolved, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.id, alert.timestamp, alert.threat_type, alert.source_ip, 
                alert.target_ip, alert.severity, alert.description, 
                alert.action_taken, alert.resolved, json.dumps(asdict(alert))
            ))
            self.conn.commit()
            
            # Log to file as well
            alert_file = os.path.join(ALERTS_DIR, f"alert_{alert.id}.json")
            with open(alert_file, 'w') as f:
                json.dump(asdict(alert), f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_command(self, command: str, source: str = "local", success: bool = True, 
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            command_id = str(uuid.uuid4())
            user = getpass.getuser()
            
            self.cursor.execute('''
                INSERT INTO commands 
                (id, command, source, success, output, execution_time, user)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (command_id, command, source, success, output[:5000], execution_time, user))
            self.conn.commit()
            
            return command_id
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
            return None
    
    def log_scan(self, scan_result: ScanResult):
        """Log scan results"""
        try:
            self.cursor.execute('''
                INSERT INTO scans 
                (id, timestamp, target, scan_type, ports, services, vulnerabilities, risk_level, raw_output, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_result.id, scan_result.timestamp, scan_result.target, 
                scan_result.scan_type, json.dumps(scan_result.ports),
                json.dumps(scan_result.services), json.dumps(scan_result.vulnerabilities),
                scan_result.risk_level, json.dumps(asdict(scan_result)), 0.0
            ))
            self.conn.commit()
            
            # Save to file
            scan_file = os.path.join(SCANS_DIR, f"scan_{scan_result.id}.json")
            with open(scan_file, 'w') as f:
                json.dump(asdict(scan_result), f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
    
    def log_traceroute(self, target: str, command: str, output: str, 
                      execution_time: float, hops: int, success: bool = True):
        """Log traceroute results"""
        try:
            result_id = str(uuid.uuid4())
            self.cursor.execute('''
                INSERT INTO traceroute_results 
                (id, target, command, output, execution_time, hops, success)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (result_id, target, command, output, execution_time, hops, success))
            self.conn.commit()
            return result_id
        except Exception as e:
            logger.error(f"Failed to log traceroute: {e}")
            return None
    
    def log_system_metrics(self):
        """Log system metrics"""
        try:
            metrics_id = str(uuid.uuid4())
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net_io = psutil.net_io_counters()
            connections = len(psutil.net_connections())
            processes = len(psutil.pids())
            
            self.cursor.execute('''
                INSERT INTO system_metrics 
                (id, cpu_percent, memory_percent, disk_percent, network_sent, 
                 network_recv, connections_count, processes_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metrics_id, cpu_percent, memory.percent, disk.percent,
                net_io.bytes_sent, net_io.bytes_recv, connections, processes
            ))
            self.conn.commit()
            return metrics_id
        except Exception as e:
            logger.error(f"Failed to log system metrics: {e}")
            return None
    
    def get_recent_threats(self, limit: int = 10, severity: str = None) -> List[Dict]:
        """Get recent threats"""
        try:
            if severity:
                self.cursor.execute('''
                    SELECT * FROM threats 
                    WHERE severity = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (severity, limit))
            else:
                self.cursor.execute('''
                    SELECT * FROM threats 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
                
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_command_history(self, limit: int = 20, source: str = None) -> List[Dict]:
        """Get command history"""
        try:
            if source:
                self.cursor.execute('''
                    SELECT command, source, timestamp, success, execution_time, user 
                    FROM commands 
                    WHERE source = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (source, limit))
            else:
                self.cursor.execute('''
                    SELECT command, source, timestamp, success, execution_time, user 
                    FROM commands 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
                
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_command_templates(self, category: str = None, search: str = None, limit: int = 50) -> List[Dict]:
        """Get command templates with search"""
        try:
            query = "SELECT * FROM command_templates WHERE 1=1"
            params = []
            
            if category:
                query += " AND category = ?"
                params.append(category)
            
            if search:
                query += " AND (name LIKE ? OR description LIKE ?)"
                params.extend([f'%{search}%', f'%{search}%'])
            
            query += " ORDER BY usage_count DESC, name LIMIT ?"
            params.append(limit)
            
            self.cursor.execute(query, params)
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command templates: {e}")
            return []
    
    def get_system_stats(self, hours: int = 24) -> Dict:
        """Get system statistics for specified hours"""
        try:
            time_threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
            
            # Get threat counts
            self.cursor.execute('''
                SELECT 
                    COUNT(*) as total_threats,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
                FROM threats 
                WHERE timestamp > ?
            ''', (time_threshold.isoformat(),))
            
            threats = self.cursor.fetchone()
            
            # Get command counts
            self.cursor.execute('''
                SELECT 
                    COUNT(*) as total_commands,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                    SUM(CASE WHEN source = 'telegram' THEN 1 ELSE 0 END) as telegram,
                    SUM(CASE WHEN source = 'local' THEN 1 ELSE 0 END) as local
                FROM commands 
                WHERE timestamp > ?
            ''', (time_threshold.isoformat(),))
            
            commands = self.cursor.fetchone()
            
            return {
                'threats': threats,
                'commands': commands,
                'time_period_hours': hours
            }
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return {}
    
    def generate_report(self, report_type: str = 'daily', format: str = 'json') -> str:
        """Generate comprehensive report"""
        try:
            report_id = str(uuid.uuid4())
            report_time = datetime.datetime.now()
            
            if report_type == 'daily':
                hours = 24
            elif report_type == 'weekly':
                hours = 168
            elif report_type == 'monthly':
                hours = 720
            else:
                hours = 24
            
            stats = self.get_system_stats(hours)
            recent_threats = self.get_recent_threats(50)
            
            report = {
                'report_id': report_id,
                'generated_at': report_time.isoformat(),
                'report_type': report_type,
                'time_period_hours': hours,
                'summary': stats,
                'recent_threats': recent_threats[:10],
                'system_info': {
                    'hostname': socket.gethostname(),
                    'os': platform.system(),
                    'os_version': platform.release(),
                    'python_version': platform.python_version(),
                    'cpu_count': psutil.cpu_count(),
                    'total_memory_gb': psutil.virtual_memory().total / (1024**3),
                    'disk_total_gb': psutil.disk_usage('/').total / (1024**3)
                }
            }
            
            # Save report
            if format == 'json':
                filename = f"report_{report_type}_{report_id}.json"
                filepath = os.path.join(REPORT_DIR, filename)
                with open(filepath, 'w') as f:
                    json.dump(report, f, indent=2)
            
            return filepath
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return ""
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except:
            pass

# ============================
# NETWORK MONITOR
# ============================
class NetworkMonitor:
    """Enhanced network monitoring and threat detection with real-time analysis"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.monitoring = False
        self.monitored_ips = set()
        self.db = db_manager
    
    def start_monitoring(self):
        """Start comprehensive network monitoring"""
        if self.monitoring:
            logger.warning("Monitoring already started")
            return
        
        self.monitoring = True
        logger.info("Starting enhanced network monitoring...")
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.monitor_port_scan, daemon=True, name="PortScanMonitor"),
            threading.Thread(target=self.monitor_syn_flood, daemon=True, name="SYNFloodMonitor"),
            threading.Thread(target=self.monitor_connections, daemon=True, name="ConnectionMonitor"),
            threading.Thread(target=self.monitor_system_metrics, daemon=True, name="SystemMetricsMonitor"),
        ]
        
        for thread in threads:
            thread.start()
        
        logger.info(f"Started {len(threads)} monitoring threads")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        logger.info("Network monitoring stopped")
    
    def monitor_port_scan(self):
        """Monitor for port scanning activity with pattern recognition"""
        logger.info("Port scan monitor started")
        port_attempts = {}
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                current_time = time.time()
                
                for conn in connections:
                    if conn.status == 'SYN_SENT' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        
                        if remote_ip not in port_attempts:
                            port_attempts[remote_ip] = {
                                'ports': set(),
                                'first_seen': current_time,
                                'last_seen': current_time,
                                'count': 0
                            }
                        
                        port_attempts[remote_ip]['ports'].add(conn.raddr.port)
                        port_attempts[remote_ip]['last_seen'] = current_time
                        port_attempts[remote_ip]['count'] += 1
                
                # Check for port scanning patterns
                for ip, data in list(port_attempts.items()):
                    time_diff = current_time - data['first_seen']
                    
                    if time_diff > 60:  # 1 minute window
                        port_count = len(data['ports'])
                        attempt_count = data['count']
                        
                        # Detect port scanning
                        if port_count > 10:
                            alert = ThreatAlert(
                                id=str(uuid.uuid4()),
                                timestamp=datetime.datetime.now().isoformat(),
                                threat_type="Port Scanning",
                                source_ip=ip,
                                target_ip="Multiple",
                                severity="high",
                                description=f"Detected port scanning activity: {port_count} ports scanned, {attempt_count} attempts",
                                action_taken="Logged and alerted",
                                resolved=False
                            )
                            
                            self.db.log_threat(alert)
                            logger.warning(f"Port scan detected from {ip}: {port_count} ports")
                            
                            # Remove from monitoring to prevent duplicate alerts
                            del port_attempts[ip]
                
                # Cleanup old entries
                old_ips = [ip for ip, data in port_attempts.items() 
                          if current_time - data['last_seen'] > 300]  # 5 minutes
                for ip in old_ips:
                    del port_attempts[ip]
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Port scan monitor error: {e}")
                time.sleep(10)
    
    def monitor_syn_flood(self):
        """Monitor for SYN flood attacks"""
        logger.info("SYN flood monitor started")
        syn_counts = {}
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                current_time = time.time()
                
                syn_count = 0
                for conn in connections:
                    if conn.status == 'SYN_SENT':
                        syn_count += 1
                
                # Track SYN counts over time
                syn_counts[current_time] = syn_count
                
                # Remove old entries (keep last 60 seconds)
                old_times = [t for t in syn_counts.keys() if current_time - t > 60]
                for t in old_times:
                    del syn_counts[t]
                
                # Calculate average over last minute
                if syn_counts:
                    avg_syn = sum(syn_counts.values()) / len(syn_counts)
                    
                    if avg_syn > 100:
                        alert = ThreatAlert(
                            id=str(uuid.uuid4()),
                            timestamp=datetime.datetime.now().isoformat(),
                            threat_type="SYN Flood",
                            source_ip="Multiple",
                            target_ip=socket.gethostbyname(socket.gethostname()),
                            severity="critical",
                            description=f"Possible SYN flood attack detected: {avg_syn:.1f} average SYN packets/second",
                            action_taken="Logged and alerted",
                            resolved=False
                        )
                        
                        self.db.log_threat(alert)
                        logger.warning(f"SYN flood detected: {avg_syn:.1f} SYN/sec")
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"SYN flood monitor error: {e}")
                time.sleep(5)
    
    def monitor_connections(self):
        """Monitor network connections for anomalies"""
        logger.info("Connection monitor started")
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                connection_stats = {
                    'total': len(connections),
                    'established': 0,
                    'syn_sent': 0,
                    'syn_recv': 0,
                    'fin_wait': 0,
                    'time_wait': 0,
                    'close_wait': 0,
                    'listen': 0,
                    'closing': 0,
                    'unknown': 0
                }
                
                for conn in connections:
                    status = conn.status.lower()
                    if status in connection_stats:
                        connection_stats[status] += 1
                    else:
                        connection_stats['unknown'] += 1
                
                # Check for anomalies
                if connection_stats['syn_sent'] > 100 and connection_stats['established'] < 10:
                    # Many SYN packets but few established connections could indicate scanning
                    pass
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
                time.sleep(10)
    
    def monitor_system_metrics(self):
        """Monitor system metrics"""
        logger.info("System metrics monitor started")
        
        while self.monitoring:
            try:
                self.db.log_system_metrics()
                time.sleep(60)  # Log every minute
            except Exception as e:
                logger.error(f"System metrics monitor error: {e}")
                time.sleep(60)
    
    def add_ip_to_monitoring(self, ip: str, notes: str = "", tags: str = ""):
        """Add IP to monitoring list"""
        try:
            ipaddress.ip_address(ip)
            self.monitored_ips.add(ip)
            
            # Add to database
            try:
                self.db.cursor.execute('''
                    INSERT OR REPLACE INTO monitored_ips 
                    (id, ip_address, notes, tags, is_active, added_date)
                    VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), ip, notes, tags))
                self.db.conn.commit()
            except Exception as e:
                logger.error(f"Failed to add IP to database: {e}")
            
            logger.info(f"Added IP to monitoring: {ip}")
            return True
        except ValueError:
            logger.error(f"Invalid IP: {ip}")
            return False
    
    def remove_ip_from_monitoring(self, ip: str):
        """Remove IP from monitoring list"""
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            
            # Update database
            try:
                self.db.cursor.execute('''
                    UPDATE monitored_ips 
                    SET is_active = 0 
                    WHERE ip_address = ?
                ''', (ip,))
                self.db.conn.commit()
            except Exception as e:
                logger.error(f"Failed to remove IP from database: {e}")
            
            logger.info(f"Removed IP from monitoring: {ip}")
            return True
        return False
    
    def get_monitored_ips(self) -> List[Dict]:
        """Get list of monitored IPs with details"""
        try:
            self.db.cursor.execute('''
                SELECT ip_address, added_date, threat_level, notes, tags 
                FROM monitored_ips 
                WHERE is_active = 1 
                ORDER BY added_date DESC
            ''')
            results = self.db.cursor.fetchall()
            
            return [{
                'ip': row[0],
                'added_date': row[1],
                'threat_level': row[2],
                'notes': row[3],
                'tags': row[4]
            } for row in results]
        except Exception as e:
            logger.error(f"Failed to get monitored IPs: {e}")
            return []

# ============================
# COMMAND EXECUTOR
# ============================
class CommandExecutor:
    """Enhanced command executor with comprehensive features"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.traceroute_tool = TracerouteTool(db_manager)
        self.command_map = self._setup_command_map()
        self.execution_history = []
    
    def _setup_command_map(self) -> Dict:
        """Setup comprehensive command execution map"""
        return {
            # Basic commands
            'ping': self.ping,
            'nmap': self.nmap,
            'curl': self.curl,
            'ssh': self.ssh,
            'whois': self.whois,
            'traceroute': self.traceroute,
            'tracert': self.traceroute,
            'advanced_traceroute': self.advanced_traceroute,
            
            # Network scanning
            'scan': self.scan,
            'deep': self.deep_scan,
            'portscan': self.port_scan,
            
            # Information gathering
            'location': self.get_ip_location,
            'analyze': self.analyze_ip,
            'dns': self.dns_lookup,
            'geo': self.geolocate,
            
            # System info
            'system': self.system_info,
            'network': self.network_info,
            'metrics': self.system_metrics,
            
            # Traffic generation
            'iperf': self.iperf,
            'hping3': self.hping3,
            
            # Network tools
            'wget': self.wget,
            'nc': self.nc,
            'dig': self.dig,
            'nslookup': self.nslookup,
            
            # Process management
            'ps': self.process_list,
            
            # File operations
            'ls': self.list_files,
            'cat': self.cat_file,
            
            # Utilities
            'clear': self.clear_screen,
            'history': self.show_history,
            'help': self.show_help,
            'exit': self.exit_tool,
        }
    
    @staticmethod
    def execute_command(cmd: str, timeout: int = 60) -> Tuple[bool, str, float]:
        """Execute shell command with timing"""
        start_time = time.time()
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                  text=True, timeout=timeout)
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                return True, result.stdout, execution_time
            else:
                error_output = result.stderr if result.stderr else result.stdout
                return False, error_output, execution_time
                
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return False, "Command timed out", execution_time
        except Exception as e:
            execution_time = time.time() - start_time
            return False, str(e), execution_time
    
    def ping(self, args: List[str]) -> str:
        """Execute ping command"""
        if not args:
            return "Usage: ping <ip> [options]"
        
        ip = args[0]
        options = args[1:] if len(args) > 1 else []
        
        if os.name == 'nt':  # Windows
            cmd = ['ping', '-n', '4'] + options + [ip]
        else:  # Linux/Mac
            cmd = ['ping', '-c', '4'] + options + [ip]
        
        success, output, exec_time = self.execute_command(' '.join(cmd))
        self.db.log_command(f"ping {' '.join(args)}", 'local', success, output[:1000], exec_time)
        
        return output if success else f"Error: {output}"
    
    def traceroute(self, args: List[str]) -> str:
        """Execute traceroute"""
        if not args:
            return "Usage: traceroute <target>"
        
        return self.traceroute_tool.interactive_traceroute(args[0])
    
    def advanced_traceroute(self, args: List[str]) -> str:
        """Execute enhanced traceroute"""
        if not args:
            return "Usage: advanced_traceroute <target>"
        
        return self.traceroute_tool.interactive_traceroute(args[0], advanced=True)
    
    def nmap(self, args: List[str]) -> str:
        """Execute nmap command"""
        if not args:
            return "Usage: nmap <ip> [options]"
        
        cmd = f"nmap {' '.join(args)}"
        self.db.log_command(cmd, 'local', True, "Starting nmap scan...", 0)
        
        print(f"Starting nmap scan: {cmd}")
        success, output, exec_time = self.execute_command(cmd, timeout=300)
        
        # Log results
        self.db.log_command(cmd, 'local', success, output[:5000], exec_time)
        
        return output if success else f"Error: {output}"
    
    def curl(self, args: List[str]) -> str:
        """Execute curl command"""
        if not args:
            return "Usage: curl <url> [options]"
        
        cmd = f"curl {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:2000], exec_time)
        
        return output if success else f"Error: {output}"
    
    def get_ip_location(self, args: List[str]) -> str:
        """Get IP location"""
        if not args:
            return "Usage: location <ip>"
        
        ip = args[0]
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    result = json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A')
                    }, indent=2)
                    
                    self.db.log_command(f"location {ip}", 'local', True, result, 0)
                    return result
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
        except Exception as e:
            return f"Location error: {str(e)}"
    
    def analyze_ip(self, args: List[str]) -> str:
        """Analyze IP comprehensively"""
        if not args:
            return "Usage: analyze <ip>"
        
        ip = args[0]
        result = f"🔍 COMPREHENSIVE ANALYSIS: {ip}\n\n"
        
        # Get location
        location = self.get_ip_location([ip])
        try:
            loc_data = json.loads(location)
            result += f"📍 GEO LOCATION\n"
            result += f"Country: {loc_data.get('country', 'N/A')}\n"
            result += f"Region: {loc_data.get('region', 'N/A')}\n"
            result += f"City: {loc_data.get('city', 'N/A')}\n"
            result += f"ISP: {loc_data.get('isp', 'N/A')}\n"
            result += f"Organization: {loc_data.get('org', 'N/A')}\n\n"
        except:
            result += f"📍 Location: {location}\n\n"
        
        # Check threats
        threats = self.db.get_recent_threats(10)
        ip_threats = [t for t in threats if t.get('source_ip') == ip or t.get('target_ip') == ip]
        
        if ip_threats:
            result += f"🚨 THREATS DETECTED: {len(ip_threats)}\n"
            for threat in ip_threats[:5]:
                result += f"• {threat.get('threat_type', 'Unknown')} ({threat.get('severity', 'Unknown')})\n"
                result += f"  Time: {threat.get('timestamp', 'Unknown')}\n"
        else:
            result += "✅ No recent threats detected\n"
        
        self.db.log_command(f"analyze {ip}", 'local', True, result, 0)
        
        return result
    
    def system_info(self, args: List[str]) -> str:
        """Get detailed system information"""
        info = []
        info.append(f"🏢 SYSTEM INFORMATION")
        info.append(f"System: {platform.system()} {platform.release()}")
        info.append(f"Architecture: {platform.machine()}")
        info.append(f"Processor: {platform.processor()}")
        info.append(f"Python: {platform.python_version()}")
        info.append("")
        
        # CPU Info
        cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
        info.append(f"💻 CPU INFORMATION")
        info.append(f"Cores: {psutil.cpu_count()} (Physical: {psutil.cpu_count(logical=False)})")
        info.append(f"Usage: {psutil.cpu_percent()}%")
        info.append(f"Per Core: {', '.join([f'{p}%' for p in cpu_percent])}")
        info.append("")
        
        # Memory Info
        mem = psutil.virtual_memory()
        info.append(f"🧠 MEMORY INFORMATION")
        info.append(f"Total: {mem.total / (1024**3):.2f} GB")
        info.append(f"Available: {mem.available / (1024**3):.2f} GB")
        info.append(f"Used: {mem.used / (1024**3):.2f} GB ({mem.percent}%)")
        info.append(f"Free: {mem.free / (1024**3):.2f} GB")
        info.append("")
        
        # Disk Info
        disk = psutil.disk_usage('/')
        info.append(f"💾 DISK INFORMATION")
        info.append(f"Total: {disk.total / (1024**3):.2f} GB")
        info.append(f"Used: {disk.used / (1024**3):.2f} GB ({disk.percent}%)")
        info.append(f"Free: {disk.free / (1024**3):.2f} GB")
        info.append("")
        
        # Network Info
        info.append(f"🌐 NETWORK INFORMATION")
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        info.append(f"Hostname: {hostname}")
        info.append(f"Local IP: {local_ip}")
        
        net_info = psutil.net_if_addrs()
        for interface, addresses in list(net_info.items())[:3]:
            info.append(f"\n{interface}:")
            for addr in addresses[:2]:
                info.append(f"  {addr.family.name}: {addr.address}")
        
        self.db.log_command("system_info", 'local', True, '\n'.join(info), 0)
        
        return '\n'.join(info)
    
    def execute(self, command: str) -> str:
        """Execute any command"""
        parts = command.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Check if command exists in map
        if cmd in self.command_map:
            try:
                start_time = time.time()
                result = self.command_map[cmd](args)
                execution_time = time.time() - start_time
                
                # Store in history
                self.execution_history.append({
                    'timestamp': datetime.datetime.now().isoformat(),
                    'command': command,
                    'execution_time': execution_time,
                    'success': True
                })
                
                return result
            except Exception as e:
                error_msg = f"Error executing {cmd}: {str(e)}"
                self.db.log_command(command, 'local', False, error_msg, 0)
                return error_msg
        else:
            # Try to execute as shell command
            success, output, exec_time = self.execute_command(command)
            self.db.log_command(command, 'local', success, output[:1000], exec_time)
            
            if success:
                return output
            else:
                return f"Unknown command: {cmd}\nType 'help' for available commands."
    
    def _show_usage(self, command: str, examples: List[str]) -> str:
        """Show command usage examples"""
        result = f"📖 {command.upper()} USAGE\n\n"
        result += "Examples:\n"
        for example in examples:
            result += f"  {example}\n"
        return result
    
    def show_history(self, args: List[str]) -> str:
        """Show command execution history"""
        limit = int(args[0]) if args else 10
        history = self.db.get_command_history(limit=limit)
        
        if not history:
            return "No command history found"
        
        result = f"📜 COMMAND HISTORY\n\n"
        
        for entry in history:
            success = "✅" if entry.get('success') else "❌"
            source = entry.get('source', 'unknown')
            cmd = entry.get('command', '')
            timestamp = entry.get('timestamp', '')
            exec_time = entry.get('execution_time', 0)
            
            result += f"{success} [{source}] {cmd}\n"
            result += f"   Time: {timestamp} | Duration: {exec_time:.2f}s\n\n"
        
        return result
    
    def show_help(self, args: List[str]) -> str:
        """Show help information"""
        categories = {
            'Network Tools': ['ping', 'traceroute', 'nmap', 'curl', 'ssh'],
            'Scanning': ['scan', 'deep', 'portscan'],
            'Information Gathering': ['location', 'analyze', 'dns', 'whois'],
            'System Info': ['system', 'network', 'metrics'],
            'Traffic Generation': ['iperf', 'hping3'],
            'Network Analysis': ['wget', 'nc', 'dig', 'nslookup'],
            'Utilities': ['clear', 'history', 'help', 'exit']
        }
        
        result = "🚀 ULTIMATE CYBERSECURITY TOOLKIT PRO v5.0\n\n"
        result += "AVAILABLE COMMANDS BY CATEGORY:\n\n"
        
        for category, commands in categories.items():
            result += f"📁 {category}\n"
            for cmd in commands:
                result += f"  {cmd}\n"
            result += "\n"
        
        result += "📖 USAGE:\n"
        result += "  command [arguments]\n\n"
        
        result += "💡 TIPS:\n"
        result += "  • All commands are logged to database\n"
        result += "  • Use 'history' to see command history\n"
        result += "  • Use 'system_info' for system details\n"
        
        return result
    
    # Additional command implementations
    def whois(self, args): 
        if not args:
            return "Usage: whois <domain>"
        domain = args[0]
        cmd = f"whois {domain}"
        success, output, exec_time = self.execute_command(cmd, timeout=30)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def dns_lookup(self, args): 
        if not args:
            return "Usage: dns <domain>"
        domain = args[0]
        try:
            ip = socket.gethostbyname(domain)
            result = f"DNS Lookup: {domain} → {ip}"
            self.db.log_command(f"dns {domain}", 'local', True, result, 0)
            return result
        except Exception as e:
            return f"Error: {str(e)}"
    
    def scan(self, args): 
        if not args:
            return "Usage: scan <ip>"
        return self.nmap([args[0], "-T4", "-F"])
    
    def deep_scan(self, args): 
        if not args:
            return "Usage: deep <ip>"
        return self.nmap([args[0], "-A", "-T4", "-p-"])
    
    def port_scan(self, args): 
        if not args:
            return "Usage: portscan <ip> [ports]"
        ports = args[1] if len(args) > 1 else "1-1000"
        return self.nmap([args[0], "-sS", f"-p{ports}"])
    
    def geolocate(self, args): 
        return self.get_ip_location(args)
    
    def network_info(self, args): 
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        result = f"🌐 NETWORK INFORMATION\n\n"
        result += f"Hostname: {hostname}\n"
        result += f"Local IP: {local_ip}\n"
        result += f"Active Connections: {len(psutil.net_connections())}\n"
        
        self.db.log_command("network_info", 'local', True, result, 0)
        return result
    
    def system_metrics(self, args): 
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        result = f"📊 SYSTEM METRICS\n\n"
        result += f"CPU Usage: {cpu}%\n"
        result += f"Memory Usage: {mem.percent}% ({mem.used / (1024**3):.1f} GB used)\n"
        result += f"Disk Usage: {disk.percent}% ({disk.used / (1024**3):.1f} GB used)\n"
        
        self.db.log_command("metrics", 'local', True, result, 0)
        return result
    
    def iperf(self, args): 
        if not args:
            return "Usage: iperf <server> [options]"
        cmd = f"iperf {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def hping3(self, args): 
        if not args:
            return "Usage: hping3 <ip> [options]"
        cmd = f"hping3 {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def wget(self, args): 
        if not args:
            return "Usage: wget <url> [options]"
        cmd = f"wget {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def nc(self, args): 
        if not args:
            return "Usage: nc <options>"
        cmd = f"nc {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def dig(self, args): 
        if not args:
            return "Usage: dig <domain> [options]"
        cmd = f"dig {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def nslookup(self, args): 
        if not args:
            return "Usage: nslookup <domain>"
        cmd = f"nslookup {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def ssh(self, args): 
        if not args:
            return "Usage: ssh <host> [options]"
        cmd = f"ssh {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd, timeout=30)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def process_list(self, args): 
        cmd = "ps aux" if not args else f"ps {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def list_files(self, args): 
        cmd = "ls -la" if not args else f"ls {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def cat_file(self, args): 
        if not args:
            return "Usage: cat <file>"
        cmd = f"cat {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def clear_screen(self, args): 
        os.system('cls' if os.name == 'nt' else 'clear')
        return "Screen cleared"
    
    def exit_tool(self, args):
        return "Type 'exit' at the main prompt to exit"

# ============================
# TELEGRAM BOT
# ============================
class TelegramBot:
    """Enhanced Telegram bot with comprehensive commands"""
    
    def __init__(self, db_manager: DatabaseManager, executor: CommandExecutor):
        self.db = db_manager
        self.executor = executor
        self.token = None
        self.chat_id = None
        self.last_update_id = 0
        self.load_config()
        self.command_handlers = self.setup_command_handlers()
    
    def load_config(self):
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.token = config.get('token')
                    self.chat_id = config.get('chat_id')
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
    
    def save_config(self):
        """Save Telegram configuration"""
        try:
            config = {
                'token': self.token,
                'chat_id': self.chat_id,
                'enabled': bool(self.token and self.chat_id)
            }
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    def setup_command_handlers(self) -> Dict:
        """Setup comprehensive command handlers"""
        handlers = {
            '/start': self.handle_start,
            '/help': self.handle_help,
            '/ping': self.handle_ping,
            '/nmap': self.handle_nmap,
            '/scan': self.handle_scan,
            '/traceroute': self.handle_traceroute,
            '/advanced_traceroute': self.handle_advanced_traceroute,
            '/curl': self.handle_curl,
            '/whois': self.handle_whois,
            '/dns': self.handle_dns,
            '/location': self.handle_location,
            '/analyze': self.handle_analyze,
            '/system': self.handle_system,
            '/network': self.handle_network,
            '/metrics': self.handle_metrics,
            '/history': self.handle_history,
            '/status': self.handle_status,
            '/report': self.handle_report,
        }
        return handlers
    
    def send_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message to Telegram with error handling"""
        if not self.token or not self.chat_id:
            logger.error("Telegram not configured")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            
            # Split long messages
            if len(message) > 4096:
                messages = [message[i:i+4000] for i in range(0, len(message), 4000)]
                for msg in messages:
                    payload = {
                        'chat_id': self.chat_id,
                        'text': msg,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': True
                    }
                    
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code != 200:
                        logger.error(f"Telegram send failed: {response.text}")
                        return False
                    time.sleep(0.5)
                return True
            else:
                payload = {
                    'chat_id': self.chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': True
                }
                
                response = requests.post(url, json=payload, timeout=10)
                
                if response.status_code == 200:
                    return True
                else:
                    logger.error(f"Telegram send failed: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Telegram send error: {e}")
            return False
    
    def get_updates(self) -> List[Dict]:
        """Get updates from Telegram"""
        if not self.token:
            return []
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getUpdates"
            params = {
                'offset': self.last_update_id + 1,
                'timeout': 30,
                'allowed_updates': ['message']
            }
            
            response = requests.get(url, params=params, timeout=35)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return data.get('result', [])
        except Exception as e:
            logger.error(f"Telegram update error: {e}")
        
        return []
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test Telegram connection"""
        if not self.token:
            return False, "Token not configured"
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    bot_info = data.get('result', {})
                    return True, f"Connected as @{bot_info.get('username', 'Unknown')}"
                else:
                    return False, f"API error: {data.get('description')}"
            else:
                return False, f"HTTP error: {response.status_code}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    # Command Handlers
    
    def handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return """
🚀 <b>ULTIMATE CYBERSECURITY TOOLKIT PRO v5.0</b> 🚀

Your comprehensive security monitoring system is online!

<b>🔍 NETWORK COMMANDS:</b>
• /ping [ip] - Ping IP address
• /nmap [ip] [options] - Complete nmap scanning
• /traceroute [ip] - Enhanced traceroute
• /scan [ip] - Quick port scan
• /advanced_traceroute [ip] - Advanced traceroute

<b>🌐 WEB & RECONNAISSANCE:</b>
• /curl [url] - HTTP requests
• /whois [domain] - WHOIS lookup
• /dns [domain] - DNS lookup
• /location [ip] - IP geolocation
• /analyze [ip] - Comprehensive analysis

<b>📊 SYSTEM INFORMATION:</b>
• /system - Detailed system info
• /network - Network information
• /metrics - Real-time metrics
• /status - System status

<b>📁 UTILITIES:</b>
• /history - Command history
• /report - Generate security report

❓ Type /help for complete command list

✅ All commands are logged and monitored
🛡️ Real-time threat detection active
📊 Database logging enabled
        """
    
    def handle_help(self, args: List[str]) -> str:
        """Handle /help command"""
        return """
<b>🔒 Complete Command Reference</b>

<b>🌐 Network Diagnostics:</b>
<code>/ping 8.8.8.8</code>
<code>/traceroute google.com</code>
<code>/advanced_traceroute 1.1.1.1</code>
<code>/scan 192.168.1.1</code>
<code>/nmap 192.168.1.1 -sS -p 80,443</code>

<b>🛡️ Security Analysis:</b>
<code>/analyze 192.168.1.1</code>
<code>/location 1.1.1.1</code>
<code>/whois example.com</code>
<code>/dns google.com</code>

<b>📊 System Info:</b>
<code>/system</code>
<code>/network</code>
<code>/metrics</code>
<code>/status</code>

<b>🌍 Web Tools:</b>
<code>/curl https://api.github.com</code>

<b>📁 Utilities:</b>
<code>/history</code>
<code>/report</code>

All commands execute instantly! 🚀
        """
    
    def handle_ping(self, args: List[str]) -> str:
        """Handle ping command"""
        if not args:
            return "❌ Usage: <code>/ping [IP]</code>"
        
        result = self.executor.ping(args)
        response = f"🏓 <b>Ping Results</b>\n\n"
        response += f"<pre>{result[-1000:]}</pre>"
        return response
    
    def handle_nmap(self, args: List[str]) -> str:
        """Handle nmap command"""
        if not args:
            return "❌ Usage: <code>/nmap [IP] [options]</code>"
        
        cmd = f"nmap {' '.join(args)}"
        self.send_message(f"🔍 <b>Starting Nmap scan...</b>\n\n<code>{cmd}</code>")
        
        result = self.executor.nmap(args)
        
        response = f"🔍 <b>Nmap Results</b>\n\n"
        if len(result) > 3000:
            response += f"<pre>{result[-3000:]}</pre>"
        else:
            response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_scan(self, args: List[str]) -> str:
        """Handle scan command"""
        if not args:
            return "❌ Usage: <code>/scan [IP]</code>"
        
        ip = args[0]
        self.send_message(f"🔍 <b>Scanning {ip}...</b>")
        
        result = self.executor.scan([ip])
        
        response = f"🔍 <b>Scan Results: {ip}</b>\n\n"
        response += f"<pre>{result[-2000:]}</pre>"
        
        return response
    
    def handle_traceroute(self, args: List[str]) -> str:
        """Handle traceroute command"""
        if not args:
            return "❌ Usage: <code>/traceroute [IP/domain]</code>"
        
        target = args[0]
        self.send_message(f"🛣️ <b>Starting traceroute to {target}...</b>")
        
        result = self.executor.traceroute([target])
        return result
    
    def handle_advanced_traceroute(self, args: List[str]) -> str:
        """Handle advanced traceroute command"""
        if not args:
            return "❌ Usage: <code>/advanced_traceroute [IP/domain]</code>"
        
        target = args[0]
        self.send_message(f"🚀 <b>Starting enhanced traceroute to {target}...</b>")
        
        result = self.executor.advanced_traceroute([target])
        return result
    
    def handle_curl(self, args: List[str]) -> str:
        """Handle curl command"""
        if not args:
            return "❌ Usage: <code>/curl [url] [options]</code>"
        
        cmd = f"curl {' '.join(args)}"
        result = self.executor.curl(args)
        
        response = f"📡 <b>CURL Results</b>\n\n"
        response += f"Command: <code>{cmd}</code>\n\n"
        
        if len(result) > 2000:
            response += f"<pre>{result[-2000:]}</pre>"
        else:
            response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_whois(self, args: List[str]) -> str:
        """Handle whois command"""
        if not args:
            return "❌ Usage: <code>/whois [domain]</code>"
        
        domain = args[0]
        result = self.executor.whois([domain])
        
        response = f"📋 <b>WHOIS: {domain}</b>\n\n"
        response += f"<pre>{result[-2000:]}</pre>"
        
        return response
    
    def handle_dns(self, args: List[str]) -> str:
        """Handle dns command"""
        if not args:
            return "❌ Usage: <code>/dns [domain]</code>"
        
        domain = args[0]
        result = self.executor.dns_lookup([domain])
        
        response = f"🌐 <b>DNS Lookup</b>\n\n"
        response += f"{result}"
        
        return response
    
    def handle_location(self, args: List[str]) -> str:
        """Handle location command"""
        if not args:
            return "❌ Usage: <code>/location [IP]</code>"
        
        ip = args[0]
        result = self.executor.get_ip_location([ip])
        
        response = f"🌍 <b>Location: {ip}</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_analyze(self, args: List[str]) -> str:
        """Handle analyze command"""
        if not args:
            return "❌ Usage: <code>/analyze [IP]</code>"
        
        ip = args[0]
        result = self.executor.analyze_ip([ip])
        
        response = f"🔍 <b>Analysis: {ip}</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_system(self, args: List[str]) -> str:
        """Handle system command"""
        result = self.executor.system_info([])
        
        response = f"💻 <b>System Information</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_network(self, args: List[str]) -> str:
        """Handle network command"""
        result = self.executor.network_info([])
        
        response = f"🌐 <b>Network Information</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_metrics(self, args: List[str]) -> str:
        """Handle metrics command"""
        result = self.executor.system_metrics([])
        
        response = f"📊 <b>System Metrics</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_history(self, args: List[str]) -> str:
        """Handle history command"""
        limit = int(args[0]) if args else 10
        history = self.db.get_command_history(limit=limit)
        
        if not history:
            return "📝 No commands recorded"
        
        response = f"📝 <b>Command History (Last {limit})</b>\n\n"
        for entry in history:
            success = "✅" if entry.get('success') else "❌"
            source = entry.get('source', 'unknown')
            cmd = entry.get('command', '')
            timestamp = entry.get('timestamp', '')
            
            response += f"{success} [{source}] <code>{cmd[:50]}</code>\n"
            response += f"   {timestamp}\n\n"
        
        return response
    
    def handle_status(self, args: List[str]) -> str:
        """Handle status command"""
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        response = "📊 <b>System Status</b>\n\n"
        response += f"✅ Bot: {'Online' if self.token else 'Offline'}\n"
        response += f"💻 CPU: {cpu}%\n"
        response += f"🧠 Memory: {mem.percent}%\n"
        response += f"💾 Disk: {disk.percent}%\n"
        response += f"🌐 Connections: {len(psutil.net_connections())}\n"
        
        return response
    
    def handle_report(self, args: List[str]) -> str:
        """Handle report command"""
        report_type = args[0] if args else 'daily'
        
        self.send_message(f"📊 <b>Generating {report_type} report...</b>")
        
        filepath = self.db.generate_report(report_type, 'json')
        
        if filepath:
            response = f"📊 <b>Security Report Generated</b>\n\n"
            response += f"Type: {report_type}\n"
            response += f"File: <code>{os.path.basename(filepath)}</code>\n"
            response += f"✅ Report saved successfully"
        else:
            response = "❌ Failed to generate report"
        
        return response
    
    def process_message(self, message: Dict):
        """Process incoming Telegram message"""
        if 'text' not in message:
            return
        
        text = message['text']
        chat_id = message['chat']['id']
        
        # Set chat ID if not set
        if not self.chat_id:
            self.chat_id = str(chat_id)
            self.save_config()
        
        # Log command
        self.db.log_command(text, 'telegram', True)
        
        parts = text.split()
        if not parts:
            return
        
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        if command in self.command_handlers:
            try:
                response = self.command_handlers[command](args)
                self.send_message(response)
            except Exception as e:
                error_msg = f"❌ Error executing command: {str(e)}"
                self.send_message(error_msg)
                logger.error(f"Command error: {e}")
        else:
            self.send_message("❌ Unknown command. Type /help for available commands.")
    
    def process_updates(self):
        """Process all pending updates"""
        updates = self.get_updates()
        
        for update in updates:
            if 'message' in update:
                self.process_message(update['message'])
            
            if 'update_id' in update:
                self.last_update_id = update['update_id']
    
    def run(self):
        """Run Telegram bot in background"""
        logger.info("Starting Telegram bot...")
        
        while True:
            try:
                self.process_updates()
                time.sleep(2)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Telegram bot error: {e}")
                time.sleep(10)

# ============================
# MAIN CYBERSECURITY TOOL
# ============================
class CyberSecurityTool:
    """Main cybersecurity tool class with comprehensive features"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.monitor = NetworkMonitor(self.db)
        self.executor = CommandExecutor(self.db)
        self.telegram = TelegramBot(self.db, self.executor)
        
        # Color scheme
        self.colors = {
            'red': Fore.RED + Style.BRIGHT,
            'green': Fore.GREEN + Style.BRIGHT,
            'yellow': Fore.YELLOW + Style.BRIGHT,
            'blue': Fore.BLUE + Style.BRIGHT,
            'cyan': Fore.CYAN + Style.BRIGHT,
            'magenta': Fore.MAGENTA + Style.BRIGHT,
            'white': Fore.WHITE + Style.BRIGHT,
            'reset': Style.RESET_ALL
        }
        
        self.running = True
        self.telegram_thread = None
    
    def print_banner(self):
        """Print enhanced tool banner"""
        banner = f"""
{self.colors['red']}╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
║{self.colors['white']}          🛡️ ACCURATE CYBER DEFENSE ULTIMATE CYBERSECURITY TOOLKIT PRO  v0.0.1 🛡️            {self.colors['red']}║
╠══════════════════════════════════════════════════════════════════════════════════════════════════╣
║{self.colors['cyan']}  • Enhanced Traceroute with Geolocation       • Advanced Network Scanning & Monitoring        {self.colors['red']}║
║{self.colors['cyan']}  • Complete Telegram Integration              • Database Logging & Reporting                 {self.colors['red']}║
║{self.colors['cyan']}  • DDoS Detection & Prevention                • Real-time Alerts & Notifications             {self.colors['red']}║
║{self.colors['cyan']}  • Traffic Generation & Load Testing          • Comprehensive Information Gathering           {self.colors['red']}║
║{self.colors['cyan']}  • System & Network Diagnostics               • Command History & Audit Trail                {self.colors['red']}║
║{self.colors['cyan']}  • Automated Security Reporting               • 50+ Built-in Security Commands               {self.colors['red']}║
╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
{self.colors['reset']}
"""
        print(banner)
    
    def print_help(self):
        """Print comprehensive help message"""
        help_text = f"""
{self.colors['yellow']}┌─────────────────{self.colors['white']} COMPLETE COMMAND REFERENCE {self.colors['yellow']}─────────────────┐
{self.colors['cyan']}
{self.colors['green']}🛡️  MONITORING & SECURITY:
{self.colors['white']}  start                    - Start threat monitoring
{self.colors['white']}  stop                     - Stop monitoring
{self.colors['white']}  status                   - Show monitoring status
{self.colors['white']}  add_ip <ip>              - Add IP to monitoring
{self.colors['white']}  remove_ip <ip>           - Remove IP from monitoring
{self.colors['white']}  list_ips                 - List monitored IPs
{self.colors['white']}  threats                  - Show recent threats
{self.colors['white']}  report [type]            - Generate security report

{self.colors['green']}📡 NETWORK DIAGNOSTICS:
{self.colors['white']}  ping <ip> [options]      - Ping with all variations
{self.colors['white']}  traceroute <ip>          - Enhanced traceroute
{self.colors['white']}  advanced_traceroute <ip> - Advanced traceroute with geolocation
{self.colors['white']}  scan ip <ip>             - Quick port scan
{self.colors['white']}  deep scan ip <ip>        - Deep port scan
{self.colors['white']}  portscan <ip> <ports>    - Custom port scan

{self.colors['green']}🔍 SCANNING & RECONNAISSANCE:
{self.colors['white']}  nmap <ip> [options]      - Complete nmap scanning
{self.colors['white']}  curl <url> [options]     - HTTP requests
{self.colors['white']}  ssh <host> [options]     - SSH connections
{self.colors['white']}  whois <domain>           - WHOIS lookup
{self.colors['white']}  dns <domain>             - DNS lookup

{self.colors['green']}🌐 INFORMATION GATHERING:
{self.colors['white']}  location <ip>            - IP geolocation
{self.colors['white']}  analyze <ip>             - Comprehensive IP analysis
{self.colors['white']}  geo <ip>                 - Quick geolocation

{self.colors['green']}🚀 NETWORK TRAFFIC GENERATION:
{self.colors['white']}  iperf <server> [options] - Bandwidth testing
{self.colors['white']}  hping3 <ip> [options]    - Traffic generation

{self.colors['green']}🔧 NETWORK TOOLS:
{self.colors['white']}  wget <options> <url>     - File download
{self.colors['white']}  nc <options>             - Netcat operations
{self.colors['white']}  dig <domain> [options]   - DNS lookup with dig
{self.colors['white']}  nslookup <domain>        - DNS lookup

{self.colors['green']}💻 SYSTEM INFORMATION:
{self.colors['white']}  system info              - Detailed system information
{self.colors['white']}  network_info             - Network information
{self.colors['white']}  metrics                  - Real-time system metrics

{self.colors['green']}📊 UTILITIES:
{self.colors['white']}  history [limit]          - Command history
{self.colors['white']}  clear                    - Clear screen
{self.colors['white']}  help                     - Show this help
{self.colors['white']}  exit                     - Exit tool

{self.colors['yellow']}└─────────────────────────────────────────────────────────────────────────────────┘
{self.colors['reset']}
{self.colors['cyan']}💡 All commands are available via Telegram!{self.colors['reset']}
{self.colors['cyan']}🚀 Use config command to setup Telegram integration.{self.colors['reset']}
"""
        print(help_text)
    
    def print_prompt(self):
        """Print command prompt"""
        prompt = f"{self.colors['red']}[{self.colors['white']}accurate-cyber-defense#{self.colors['red']}]{self.colors['reset']} "
        return input(prompt)
    
    def process_command(self, command: str):
        """Process user command"""
        if not command.strip():
            return
        
        result = self.executor.execute(command)
        if result:
            print(result)
    
    def start_telegram_bot(self):
        """Start Telegram bot in background"""
        if self.telegram.token and self.telegram.chat_id:
            self.telegram_thread = threading.Thread(target=self.telegram.run, daemon=True)
            self.telegram_thread.start()
            logger.info("Telegram bot started")
        else:
            logger.warning("Telegram not configured. Bot not started.")
    
    def setup_telegram(self):
        """Setup Telegram configuration"""
        print(f"\n{self.colors['cyan']}🔧 Telegram Bot Setup{self.colors['reset']}")
        print("=" * 60)
        print("\nTo use Telegram commands:")
        print("1. Create a bot with @BotFather on Telegram")
        print("2. Get your bot token")
        print("3. Start chat with your bot and send /start")
        print("4. Get your chat ID from @userinfobot\n")
        
        setup = input("Configure Telegram now? (y/n): ").lower()
        if setup == 'y':
            token = input("Enter Telegram bot token: ").strip()
            chat_id = input("Enter your chat ID: ").strip()
            
            if token and chat_id:
                self.telegram.token = token
                self.telegram.chat_id = chat_id
                self.telegram.save_config()
                
                print(f"{self.colors['green']}✅ Telegram configured!{self.colors['reset']}")
                
                # Test connection
                success, message = self.telegram.test_connection()
                if success:
                    print(f"{self.colors['green']}✅ {message}{self.colors['reset']}")
                    
                    # Send welcome message
                    welcome_msg = """🚀 <b>ULTIMATE CYBERSECURITY TOOLKIT PRO v5.0 - Connected!</b>

✅ Bot is online and ready
🚀 Type /help for commands
🛡️ Security monitoring active
📊 Database logging enabled

Your comprehensive security toolkit is now available via Telegram!"""
                    self.telegram.send_message(welcome_msg)
                else:
                    print(f"{self.colors['red']}❌ {message}{self.colors['reset']}")
            else:
                print(f"{self.colors['yellow']}⚠️ Telegram configuration cancelled{self.colors['reset']}")
    
    def check_dependencies(self):
        """Check and install required dependencies"""
        print(f"{self.colors['cyan']}🔍 Checking dependencies...{self.colors['reset']}")
        
        required_packages = ['requests', 'psutil', 'colorama']
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package)
                print(f"✅ {package}")
            except ImportError:
                print(f"⚠️ {package} not installed")
                missing_packages.append(package)
        
        if missing_packages:
            print(f"\n{self.colors['yellow']}Some dependencies are missing.{self.colors['reset']}")
            install = input(f"Install missing packages? (y/n): ").lower()
            if install == 'y':
                for package in missing_packages:
                    try:
                        print(f"Installing {package}...")
                        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                        print(f"✅ {package} installed")
                    except Exception as e:
                        print(f"❌ Failed to install {package}: {e}")
    
    def run(self):
        """Main run loop"""
        # Clear screen and show banner
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        # Check dependencies
        self.check_dependencies()
        
        # Setup Telegram
        if not self.telegram.token or not self.telegram.chat_id:
            self.setup_telegram()
        
        # Start Telegram bot
        self.start_telegram_bot()
        
        print(f"\n{self.colors['green']}✅ Ultimate Cybersecurity Toolkit Pro v5.0 is ready!{self.colors['reset']}")
        print(f"{self.colors['cyan']}💡 Type 'help' for commands{self.colors['reset']}")
        
        if self.telegram.token and self.telegram.chat_id:
            print(f"{self.colors['green']}🤖 Telegram bot: ACTIVE{self.colors['reset']}")
            print(f"{self.colors['cyan']}📱 Send /start to your bot on Telegram{self.colors['reset']}")
        
        print(f"{self.colors['yellow']}⚠️  Use responsibly and only on networks you own or have permission to test{self.colors['reset']}")
        
        # Main command loop
        while self.running:
            try:
                command = self.print_prompt()
                
                if command.lower() == 'exit':
                    print(f"\n{self.colors['yellow']}Exiting...{self.colors['reset']}")
                    self.running = False
                elif command.lower() == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.print_banner()
                elif command.lower() == 'help':
                    self.print_help()
                elif command.lower() == 'start':
                    self.monitor.start_monitoring()
                    print(f"{self.colors['green']}✅ Monitoring started{self.colors['reset']}")
                elif command.lower() == 'stop':
                    self.monitor.stop_monitoring()
                    print(f"{self.colors['yellow']}⚠️ Monitoring stopped{self.colors['reset']}")
                elif command.lower().startswith('add_ip'):
                    parts = command.split()
                    if len(parts) > 1:
                        self.monitor.add_ip_to_monitoring(parts[1])
                        print(f"{self.colors['green']}✅ Added {parts[1]} to monitoring{self.colors['reset']}")
                    else:
                        print(f"{self.colors['red']}❌ Usage: add_ip <ip>{self.colors['reset']}")
                elif command.lower().startswith('remove_ip'):
                    parts = command.split()
                    if len(parts) > 1:
                        self.monitor.remove_ip_from_monitoring(parts[1])
                        print(f"{self.colors['green']}✅ Removed {parts[1]} from monitoring{self.colors['reset']}")
                    else:
                        print(f"{self.colors['red']}❌ Usage: remove_ip <ip>{self.colors['reset']}")
                elif command.lower() == 'list_ips':
                    ips = self.monitor.get_monitored_ips()
                    if ips:
                        print(f"\n{self.colors['cyan']}📋 Monitored IPs:{self.colors['reset']}")
                        for ip_info in ips:
                            print(f"  • {ip_info['ip']} (Added: {ip_info['added_date']})")
                    else:
                        print(f"{self.colors['yellow']}📋 No IPs are being monitored{self.colors['reset']}")
                elif command.lower() == 'threats':
                    threats = self.db.get_recent_threats(10)
                    if threats:
                        print(f"\n{self.colors['red']}🚨 Recent Threats:{self.colors['reset']}")
                        for threat in threats:
                            print(f"  • {threat.get('source_ip')} - {threat.get('threat_type')} ({threat.get('severity')})")
                            print(f"    Time: {threat.get('timestamp')}\n")
                    else:
                        print(f"{self.colors['green']}✅ No recent threats detected{self.colors['reset']}")
                elif command.lower().startswith('report'):
                    parts = command.split()
                    report_type = parts[1] if len(parts) > 1 else 'daily'
                    filepath = self.db.generate_report(report_type, 'json')
                    if filepath:
                        print(f"{self.colors['green']}✅ Report generated: {filepath}{self.colors['reset']}")
                    else:
                        print(f"{self.colors['red']}❌ Failed to generate report{self.colors['reset']}")
                elif command.lower() == 'config':
                    self.setup_telegram()
                else:
                    self.process_command(command)
                    
            except KeyboardInterrupt:
                print(f"\n{self.colors['yellow']}Exiting...{self.colors['reset']}")
                self.running = False
            except Exception as e:
                print(f"{self.colors['red']}Error: {str(e)}{self.colors['reset']}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.db.close()
        print(f"{self.colors['green']}Tool shutdown complete.{self.colors['reset']}")

# ============================
# MAIN ENTRY POINT
# ============================
def main():
    """Main entry point"""
    try:
        # Create tool instance
        tool = CyberSecurityTool()
        
        # Run tool
        tool.run()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Tool interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"{Fore.RED}Fatal error occurred. Check {LOG_FILE} for details.{Style.RESET_ALL}")
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()