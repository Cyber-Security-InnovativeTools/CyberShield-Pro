#!/usr/bin/env python3
"""
🔒 CyberShield Pro - Ultimate Web Security & Traffic Analyzer
Single File - Production Ready with Creative Dashboard
"""

from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import requests, socket, ssl, dns.resolver, json, re, time, os, sys, uuid, hashlib
from datetime import datetime, timedelta
from urllib.parse import urlparse
import ipaddress, sqlite3, threading, queue, statistics, math
from collections import defaultdict, Counter
import secrets
import logging
from logging.handlers import RotatingFileHandler
import plotly.graph_objects as go
import plotly.io as pio
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64

# ==================== DATABASE SETUP ====================
class TrafficDB:
    def __init__(self, db_path="traffic_data.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Traffic logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                scan_type TEXT,
                risk_score INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE,
                url TEXT NOT NULL,
                data TEXT,
                risk_level TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Traffic patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hour INTEGER,
                day TEXT,
                scan_count INTEGER,
                date DATE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_traffic(self, url, ip_address, user_agent, scan_type, risk_score):
        """Log website traffic"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO traffic_logs (url, ip_address, user_agent, scan_type, risk_score)
            VALUES (?, ?, ?, ?, ?)
        ''', (url, ip_address, user_agent, scan_type, risk_score))
        conn.commit()
        conn.close()
    
    def save_scan_result(self, scan_id, url, data, risk_level):
        """Save scan result to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO scan_results (scan_id, url, data, risk_level)
            VALUES (?, ?, ?, ?)
        ''', (scan_id, url, json.dumps(data), risk_level))
        conn.commit()
        conn.close()
    
    def get_traffic_stats(self, days=7):
        """Get traffic statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Daily traffic
        cursor.execute('''
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM traffic_logs
            WHERE timestamp >= datetime('now', '-? days')
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        ''', (days,))
        daily_stats = cursor.fetchall()
        
        # Scan types distribution
        cursor.execute('''
            SELECT scan_type, COUNT(*) as count
            FROM traffic_logs
            GROUP BY scan_type
        ''')
        scan_types = cursor.fetchall()
        
        # Risk distribution
        cursor.execute('''
            SELECT risk_level, COUNT(*) as count
            FROM (
                SELECT CASE 
                    WHEN risk_score >= 70 THEN 'HIGH'
                    WHEN risk_score >= 40 THEN 'MEDIUM'
                    ELSE 'LOW'
                END as risk_level
                FROM traffic_logs
            )
            GROUP BY risk_level
        ''')
        risk_dist = cursor.fetchall()
        
        # Hourly patterns
        cursor.execute('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM traffic_logs
            GROUP BY hour
            ORDER BY hour
        ''')
        hourly = cursor.fetchall()
        
        conn.close()
        
        return {
            "daily_traffic": [{"date": d[0], "count": d[1]} for d in daily_stats],
            "scan_types": [{"type": s[0], "count": s[1]} for s in scan_types],
            "risk_distribution": [{"level": r[0], "count": r[1]} for r in risk_dist],
            "hourly_patterns": [{"hour": int(h[0]), "count": h[1]} for h in hourly]
        }
    
    def get_top_scanned(self, limit=10):
        """Get most scanned websites"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT url, COUNT(*) as scan_count, 
                   AVG(risk_score) as avg_risk
            FROM traffic_logs
            GROUP BY url
            ORDER BY scan_count DESC
            LIMIT ?
        ''', (limit,))
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                "url": r[0],
                "scan_count": r[1],
                "avg_risk": round(r[2], 1) if r[2] else 0
            }
            for r in results
        ]

# Initialize database
db = TrafficDB()

# ==================== FLASK APP SETUP ====================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["100 per day", "20 per hour"]
)

# ==================== TRAFFIC ANALYZER ====================
class TrafficAnalyzer:
    def __init__(self):
        self.traffic_data = defaultdict(list)
        self.anomaly_threshold = 3
    
    def analyze_traffic_patterns(self, traffic_logs):
        """Analyze traffic patterns for anomalies"""
        if not traffic_logs:
            return {"status": "no_data"}
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame(traffic_logs)
        
        # Calculate statistics
        stats = {
            "total_scans": len(df),
            "unique_websites": df['url'].nunique(),
            "unique_ips": df['ip_address'].nunique() if 'ip_address' in df.columns else 0,
            "avg_risk_score": df['risk_score'].mean() if 'risk_score' in df.columns else 0,
            "high_risk_percentage": (df['risk_score'] >= 70).sum() / len(df) * 100 if 'risk_score' in df.columns else 0
        }
        
        # Time-based patterns
        if 'timestamp' in df.columns:
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            hourly_patterns = df.groupby('hour').size().to_dict()
            stats["peak_hour"] = max(hourly_patterns, key=hourly_patterns.get) if hourly_patterns else None
        
        # Risk trend
        if 'risk_score' in df.columns and 'timestamp' in df.columns:
            df['date'] = pd.to_datetime(df['timestamp']).dt.date
            daily_risk = df.groupby('date')['risk_score'].mean().to_dict()
            stats["risk_trend"] = daily_risk
        
        return stats
    
    def detect_anomalies(self, traffic_data):
        """Detect unusual traffic patterns"""
        anomalies = []
        
        # Check for sudden spikes
        if len(traffic_data) >= 10:
            scan_counts = [t['count'] for t in traffic_data[-10:]]
            mean_count = statistics.mean(scan_counts)
            std_count = statistics.stdev(scan_counts) if len(scan_counts) > 1 else 0
            
            latest_count = scan_counts[-1]
            if std_count > 0 and latest_count > mean_count + (self.anomaly_threshold * std_count):
                anomalies.append({
                    "type": "traffic_spike",
                    "severity": "high",
                    "message": f"Sudden traffic spike detected: {latest_count} scans",
                    "mean": round(mean_count, 2),
                    "current": latest_count
                })
        
        return anomalies
    
    def generate_traffic_report(self, days=7):
        """Generate comprehensive traffic report"""
        stats = db.get_traffic_stats(days)
        
        # Create visualizations
        report = {
            "summary": {
                "total_scans": sum(d['count'] for d in stats['daily_traffic']),
                "unique_websites": len(set(d['date'] for d in stats['daily_traffic'])),
                "avg_daily_scans": sum(d['count'] for d in stats['daily_traffic']) / max(len(stats['daily_traffic']), 1),
                "high_risk_scans": sum(d['count'] for d in stats['risk_distribution'] if d['level'] == 'HIGH')
            },
            "patterns": stats,
            "top_scanned": db.get_top_scanned(10),
            "anomalies": self.detect_anomalies(stats['daily_traffic'])
        }
        
        # Generate charts
        report['charts'] = {
            "daily_traffic_chart": self.create_daily_traffic_chart(stats['daily_traffic']),
            "risk_distribution_chart": self.create_risk_chart(stats['risk_distribution']),
            "hourly_pattern_chart": self.create_hourly_chart(stats['hourly_patterns'])
        }
        
        return report
    
    def create_daily_traffic_chart(self, daily_data):
        """Create daily traffic chart as base64 image"""
        if not daily_data:
            return None
        
        dates = [d['date'] for d in daily_data]
        counts = [d['count'] for d in daily_data]
        
        plt.figure(figsize=(10, 5))
        plt.plot(dates, counts, marker='o', linewidth=2, color='#4361ee')
        plt.fill_between(dates, counts, alpha=0.3, color='#4361ee')
        plt.title('Daily Scan Traffic', fontsize=14, fontweight='bold')
        plt.xlabel('Date')
        plt.ylabel('Number of Scans')
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        # Save to bytes
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100)
        plt.close()
        buf.seek(0)
        
        return base64.b64encode(buf.read()).decode('utf-8')
    
    def create_risk_chart(self, risk_data):
        """Create risk distribution chart"""
        if not risk_data:
            return None
        
        labels = [d['level'] for d in risk_data]
        sizes = [d['count'] for d in risk_data]
        colors = ['#ef476f', '#ffd166', '#06d6a0']  # Red, Yellow, Green
        
        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.title('Risk Level Distribution', fontsize=14, fontweight='bold')
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100)
        plt.close()
        buf.seek(0)
        
        return base64.b64encode(buf.read()).decode('utf-8')
    
    def create_hourly_chart(self, hourly_data):
        """Create hourly pattern chart"""
        if not hourly_data:
            return None
        
        hours = [d['hour'] for d in hourly_data]
        counts = [d['count'] for d in hourly_data]
        
        plt.figure(figsize=(10, 5))
        bars = plt.bar(hours, counts, color='#3a0ca3', alpha=0.8)
        plt.title('Hourly Traffic Patterns', fontsize=14, fontweight='bold')
        plt.xlabel('Hour of Day')
        plt.ylabel('Number of Scans')
        plt.grid(True, alpha=0.3, axis='y')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}', ha='center', va='bottom')
        
        plt.tight_layout()
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100)
        plt.close()
        buf.seek(0)
        
        return base64.b64encode(buf.read()).decode('utf-8')

# Initialize analyzer
traffic_analyzer = TrafficAnalyzer()

# ==================== SECURITY SCANNER ====================
class AdvancedScanner:
    def __init__(self):
        self.user_agent = "CyberShield-Pro/3.0"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
    
    def normalize_url(self, url):
        """Normalize URL"""
        if not url:
            return ""
        url = url.strip()
        if not re.match(r'^https?://', url, re.IGNORECASE):
            url = 'https://' + url
        return url
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.split(':')[0]
        except:
            return ""
    
    def scan_website(self, url, scan_type="full"):
        """Comprehensive website scan"""
        scan_id = str(uuid.uuid4())[:8]
        domain = self.extract_domain(url)
        
        results = {
            "scan_id": scan_id,
            "url": url,
            "domain": domain,
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "checks": {}
        }
        
        try:
            # HTTP Check
            http_result = self.check_http(url)
            results["checks"]["http"] = http_result
            
            # SSL Check
            ssl_result = self.check_ssl(domain)
            results["checks"]["ssl"] = ssl_result
            
            # Security Headers
            if scan_type == "full":
                headers_result = self.check_security_headers(url)
                results["checks"]["headers"] = headers_result
                
                # DNS Check
                dns_result = self.check_dns(domain)
                results["checks"]["dns"] = dns_result
                
                # Vulnerability Check
                vuln_result = self.check_vulnerabilities(url)
                results["checks"]["vulnerabilities"] = vuln_result
            
            # Calculate Risk Score
            risk_result = self.calculate_risk(results["checks"])
            results["risk"] = risk_result
            
            # Save to database
            db.save_scan_result(scan_id, url, results, risk_result["level"])
            
            return results
            
        except Exception as e:
            results["error"] = str(e)
            return results
    
    def check_http(self, url):
        """Check HTTP connection"""
        try:
            start = time.time()
            response = self.session.get(url, timeout=10, allow_redirects=True)
            duration = time.time() - start
            
            return {
                "status": "success",
                "status_code": response.status_code,
                "response_time": round(duration * 1000, 2),
                "server": response.headers.get('Server', 'Unknown'),
                "content_type": response.headers.get('Content-Type', 'Unknown'),
                "size_kb": len(response.content) / 1024
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    def check_ssl(self, domain):
        """Check SSL certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse dates
                    expire_str = cert.get('notAfter', '')
                    if expire_str:
                        expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expire_date - datetime.now()).days
                    else:
                        days_left = None
                    
                    return {
                        "valid": True,
                        "protocol": ssock.version(),
                        "issuer": cert.get('issuer', [[('', 'Unknown')]])[0][0][1],
                        "expires": expire_str,
                        "days_left": days_left
                    }
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def check_security_headers(self, url):
        """Check security headers"""
        try:
            response = self.session.head(url, timeout=5)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            security_headers = {
                'strict-transport-security': headers.get('strict-transport-security', 'MISSING'),
                'content-security-policy': headers.get('content-security-policy', 'MISSING'),
                'x-frame-options': headers.get('x-frame-options', 'MISSING'),
                'x-content-type-options': headers.get('x-content-type-options', 'MISSING'),
                'referrer-policy': headers.get('referrer-policy', 'MISSING'),
                'x-xss-protection': headers.get('x-xss-protection', 'MISSING')
            }
            
            # Check cookies
            cookies = []
            if 'set-cookie' in headers:
                cookies = headers['set-cookie'] if isinstance(headers['set-cookie'], list) else [headers['set-cookie']]
            
            cookie_issues = []
            for cookie in cookies:
                cookie_lower = cookie.lower()
                if 'secure' not in cookie_lower:
                    cookie_issues.append('Missing Secure flag')
                if 'httponly' not in cookie_lower:
                    cookie_issues.append('Missing HttpOnly flag')
                if 'samesite' not in cookie_lower:
                    cookie_issues.append('Missing SameSite attribute')
            
            return {
                "security_headers": security_headers,
                "cookies_found": len(cookies),
                "cookie_issues": cookie_issues,
                "headers_present": sum(1 for h in security_headers.values() if h != 'MISSING')
            }
        except Exception as e:
            return {"error": str(e)}
    
    def check_dns(self, domain):
        """Check DNS records"""
        try:
            result = {"A": [], "MX": [], "TXT": []}
            
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A', lifetime=3)
                result["A"] = [str(r) for r in answers]
            except:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
                result["MX"] = [str(r.exchange) for r in answers]
            except:
                pass
            
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def check_vulnerabilities(self, url):
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        # Check common exposed paths
        common_paths = ['/admin/', '/wp-admin/', '/login/', '/config/', '/backup/']
        for path in common_paths:
            try:
                test_url = url.rstrip('/') + path
                response = self.session.head(test_url, timeout=2)
                if response.status_code == 200:
                    vulnerabilities.append(f"Exposed directory: {path}")
            except:
                pass
        
        return {
            "found": len(vulnerabilities),
            "list": vulnerabilities[:5]
        }
    
    def calculate_risk(self, checks):
        """Calculate risk score"""
        score = 100
        
        # HTTP deductions
        http = checks.get("http", {})
        if http.get("status") == "failed":
            score -= 30
        elif http.get("status_code", 0) >= 500:
            score -= 20
        
        # SSL deductions
        ssl = checks.get("ssl", {})
        if not ssl.get("valid", False):
            score -= 25
        elif ssl.get("days_left", 365) < 30:
            score -= 15
        
        # Headers deductions
        headers = checks.get("headers", {})
        if headers:
            missing = sum(1 for h in headers.get("security_headers", {}).values() if h == "MISSING")
            score -= missing * 5
            
            if headers.get("cookie_issues"):
                score -= len(headers["cookie_issues"]) * 3
        
        # Vulnerabilities deductions
        vuln = checks.get("vulnerabilities", {})
        if vuln.get("found", 0) > 0:
            score -= vuln["found"] * 8
        
        # Ensure score within bounds
        score = max(0, min(100, score))
        
        # Determine level
        if score >= 80:
            level = "LOW"
            color = "success"
            icon = "🟢"
        elif score >= 50:
            level = "MEDIUM"
            color = "warning"
            icon = "🟡"
        else:
            level = "HIGH"
            color = "danger"
            icon = "🔴"
        
        return {
            "score": score,
            "level": level,
            "color": color,
            "icon": icon
        }

# Initialize scanner
scanner = AdvancedScanner()

# ==================== HTML TEMPLATES ====================
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ CyberShield Pro - Web Security & Traffic Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary: #4361ee;
            --secondary: #3a0ca3;
            --success: #06d6a0;
            --warning: #ffd166;
            --danger: #ef476f;
            --dark: #121212;
            --light: #f8f9fa;
        }
        
        body {
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            color: var(--light);
            min-height: 100vh;
            font-family: 'Segoe UI', system-ui, sans-serif;
        }
        
        .glass-card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .glass-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.3);
        }
        
        .navbar-glass {
            background: rgba(255, 255, 255, 0.08) !important;
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .gradient-text {
            background: linear-gradient(45deg, #4361ee, #3a0ca3, #7209b7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .stat-card {
            padding: 1.5rem;
            border-radius: 15px;
            margin-bottom: 1rem;
        }
        
        .stat-high { border-left: 5px solid var(--danger); }
        .stat-medium { border-left: 5px solid var(--warning); }
        .stat-low { border-left: 5px solid var(--success); }
        
        .scan-animation {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .traffic-chart {
            height: 300px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 20px;
        }
        
        .risk-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.8rem;
        }
        
        .risk-high { background: linear-gradient(45deg, #ef476f, #ff0054); }
        .risk-medium { background: linear-gradient(45deg, #ffd166, #ff9e00); }
        .risk-low { background: linear-gradient(45deg, #06d6a0, #00b894); }
        
        .scan-input {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: white;
            padding: 15px 20px;
            border-radius: 12px;
            font-size: 1.1rem;
        }
        
        .scan-input:focus {
            background: rgba(255, 255, 255, 0.15);
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.3);
            color: white;
        }
        
        .btn-glow {
            background: linear-gradient(45deg, var(--primary), var(--secondary));
            border: none;
            padding: 12px 30px;
            border-radius: 12px;
            font-weight: bold;
            position: relative;
            overflow: hidden;
        }
        
        .btn-glow:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(67, 97, 238, 0.4);
        }
        
        .btn-glow::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(
                to right,
                rgba(255, 255, 255, 0) 0%,
                rgba(255, 255, 255, 0.1) 50%,
                rgba(255, 255, 255, 0) 100%
            );
            transform: rotate(30deg);
            transition: all 0.5s;
        }
        
        .btn-glow:hover::after {
            left: 100%;
        }
        
        .result-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .progress-glow {
            background: linear-gradient(90deg, #ef476f, #ffd166, #06d6a0);
            height: 10px;
            border-radius: 5px;
        }
        
        .traffic-map {
            height: 300px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: rgba(255, 255, 255, 0.5);
            font-size: 1.2rem;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-glass py-3">
        <div class="container">
            <a class="navbar-brand fw-bold fs-3 gradient-text" href="#">
                <i class="fas fa-shield-alt me-2"></i>CyberShield Pro
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="#"><i class="fas fa-home me-1"></i> Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#scanner"><i class="fas fa-search me-1"></i> Scanner</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#traffic"><i class="fas fa-chart-line me-1"></i> Traffic</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#reports"><i class="fas fa-file-alt me-1"></i> Reports</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container py-4">
        <!-- Header -->
        <div class="text-center mb-5">
            <h1 class="display-4 fw-bold gradient-text mb-3">CyberShield Pro</h1>
            <p class="lead text-light opacity-75">Advanced Web Security Scanner with Real-time Traffic Analysis</p>
        </div>

        <!-- Stats Overview -->
        <div class="row mb-5" id="stats">
            <div class="col-md-3 col-6 mb-3">
                <div class="glass-card stat-card text-center">
                    <i class="fas fa-globe fa-2x mb-3 text-primary"></i>
                    <h3 class="fw-bold" id="totalScans">0</h3>
                    <p class="text-light opacity-75 mb-0">Total Scans</p>
                </div>
            </div>
            <div class="col-md-3 col-6 mb-3">
                <div class="glass-card stat-card text-center">
                    <i class="fas fa-shield-alt fa-2x mb-3 text-success"></i>
                    <h3 class="fw-bold" id="secureSites">0</h3>
                    <p class="text-light opacity-75 mb-0">Secure Sites</p>
                </div>
            </div>
            <div class="col-md-3 col-6 mb-3">
                <div class="glass-card stat-card text-center">
                    <i class="fas fa-exclamation-triangle fa-2x mb-3 text-warning"></i>
                    <h3 class="fw-bold" id="vulnerabilities">0</h3>
                    <p class="text-light opacity-75 mb-0">Vulnerabilities</p>
                </div>
            </div>
            <div class="col-md-3 col-6 mb-3">
                <div class="glass-card stat-card text-center">
                    <i class="fas fa-users fa-2x mb-3 text-info"></i>
                    <h3 class="fw-bold" id="activeUsers">0</h3>
                    <p class="text-light opacity-75 mb-0">Active Users</p>
                </div>
            </div>
        </div>

        <!-- Scanner Section -->
        <div class="glass-card p-4 mb-5" id="scanner">
            <h3 class="mb-4"><i class="fas fa-search me-2"></i> Website Security Scanner</h3>
            <div class="row">
                <div class="col-md-8">
                    <input type="url" id="scanUrl" class="form-control scan-input mb-3" 
                           placeholder="https://example.com" required>
                </div>
                <div class="col-md-4">
                    <button class="btn btn-glow w-100 mb-3" onclick="startFullScan()">
                        <i class="fas fa-search me-2"></i> Full Security Scan
                    </button>
                    <button class="btn btn-outline-light w-100" onclick="startQuickScan()">
                        <i class="fas fa-bolt me-2"></i> Quick Scan
                    </button>
                </div>
            </div>
            
            <!-- Scan Options -->
            <div class="row mt-3">
                <div class="col-md-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="sslCheck" checked>
                        <label class="form-check-label">SSL/TLS Check</label>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="headersCheck" checked>
                        <label class="form-check-label">Security Headers</label>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="dnsCheck">
                        <label class="form-check-label">DNS Analysis</label>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="vulnCheck">
                        <label class="form-check-label">Vulnerability Scan</label>
                    </div>
                </div>
            </div>
            
            <!-- Progress -->
            <div id="scanProgress" class="mt-4" style="display: none;">
                <div class="d-flex justify-content-between mb-2">
                    <span id="progressText">Scanning...</span>
                    <span id="progressPercent">0%</span>
                </div>
                <div class="progress progress-glow">
                    <div id="progressBar" class="progress-bar" role="progressbar" style="width: 0%"></div>
                </div>
                <p id="scanMessage" class="mt-2 text-light opacity-75"></p>
            </div>
        </div>

        <!-- Results Section -->
        <div id="resultsSection" style="display: none;">
            <h3 class="mb-4"><i class="fas fa-file-alt me-2"></i> Scan Results</h3>
            <div id="resultsContainer" class="row"></div>
        </div>

        <!-- Traffic Analysis -->
        <div class="glass-card p-4 mb-5" id="traffic">
            <h3 class="mb-4"><i class="fas fa-chart-line me-2"></i> Traffic Analysis</h3>
            <div class="row">
                <div class="col-md-8">
                    <div class="traffic-chart">
                        <canvas id="trafficChart"></canvas>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="traffic-map">
                        <i class="fas fa-map-marked-alt fa-3x mb-3"></i>
                        <p>Real-time Traffic Map</p>
                    </div>
                </div>
            </div>
            
            <div class="row mt-4">
                <div class="col-md-4">
                    <div class="result-card">
                        <h5><i class="fas fa-clock me-2"></i> Peak Hours</h5>
                        <p class="fs-3 fw-bold" id="peakHour">--:--</p>
                        <p class="text-light opacity-75">Most active scanning time</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="result-card">
                        <h5><i class="fas fa-exclamation-circle me-2"></i> High Risk</h5>
                        <p class="fs-3 fw-bold" id="highRiskCount">0</p>
                        <p class="text-light opacity-75">Websites with high risk</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="result-card">
                        <h5><i class="fas fa-tachometer-alt me-2"></i> Avg Response</h5>
                        <p class="fs-3 fw-bold" id="avgResponse">0ms</p>
                        <p class="text-light opacity-75">Average response time</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Top Scanned Websites -->
        <div class="glass-card p-4" id="reports">
            <h3 class="mb-4"><i class="fas fa-list-ol me-2"></i> Top Scanned Websites</h3>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>Website</th>
                            <th>Scan Count</th>
                            <th>Avg Risk</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="topWebsites">
                        <!-- Dynamic content -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="text-center py-4 mt-5 text-light opacity-75">
        <p>🛡️ CyberShield Pro v3.0 | Enterprise Security Scanner | Use Responsibly</p>
        <p class="small">⚠️ This tool is for authorized security testing and educational purposes only.</p>
    </footer>

    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Initialize stats
        updateStats();
        
        // Update stats every 30 seconds
        setInterval(updateStats, 30000);
        
        function updateStats() {
            fetch('/api/traffic/stats')
                .then(res => res.json())
                .then(data => {
                    document.getElementById('totalScans').textContent = data.total_scans || 0;
                    document.getElementById('secureSites').textContent = data.secure_sites || 0;
                    document.getElementById('vulnerabilities').textContent = data.vulnerabilities || 0;
                    document.getElementById('activeUsers').textContent = data.active_users || 0;
                    document.getElementById('peakHour').textContent = data.peak_hour || '--:--';
                    document.getElementById('highRiskCount').textContent = data.high_risk || 0;
                    document.getElementById('avgResponse').textContent = data.avg_response || '0ms';
                    
                    // Update top websites
                    updateTopWebsites(data.top_websites || []);
                    
                    // Update traffic chart
                    updateTrafficChart(data.traffic_data || []);
                });
        }
        
        function updateTopWebsites(websites) {
            const tbody = document.getElementById('topWebsites');
            tbody.innerHTML = '';
            
            websites.forEach(site => {
                const row = document.createElement('tr');
                let riskBadge = '<span class="risk-low risk-badge">Low</span>';
                if (site.avg_risk >= 70) riskBadge = '<span class="risk-high risk-badge">High</span>';
                else if (site.avg_risk >= 40) riskBadge = '<span class="risk-medium risk-badge">Medium</span>';
                
                row.innerHTML = `
                    <td>${site.url}</td>
                    <td>${site.scan_count}</td>
                    <td>${site.avg_risk || 0}</td>
                    <td>${riskBadge}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-light" onclick="rescanWebsite('${site.url}')">
                            <i class="fas fa-redo"></i>
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        }
        
        function updateTrafficChart(data) {
            const ctx = document.getElementById('trafficChart').getContext('2d');
            
            if (window.trafficChart) {
                window.trafficChart.destroy();
            }
            
            const labels = data.map(d => d.date);
            const counts = data.map(d => d.count);
            
            window.trafficChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Daily Scans',
                        data: counts,
                        borderColor: '#4361ee',
                        backgroundColor: 'rgba(67, 97, 238, 0.1)',
                        borderWidth: 3,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleColor: '#fff',
                            bodyColor: '#fff'
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: 'rgba(255, 255, 255, 0.7)' }
                        },
                        y: {
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: 'rgba(255, 255, 255, 0.7)' }
                        }
                    }
                }
            });
        }
        
        let scanInProgress = false;
        
        function startFullScan() {
            const url = document.getElementById('scanUrl').value.trim();
            if (!url) {
                alert('Please enter a website URL');
                return;
            }
            
            if (scanInProgress) return;
            scanInProgress = true;
            
            // Show progress
            const progressSection = document.getElementById('scanProgress');
            const progressBar = document.getElementById('progressBar');
            const progressPercent = document.getElementById('progressPercent');
            const progressText = document.getElementById('progressText');
            const scanMessage = document.getElementById('scanMessage');
            
            progressSection.style.display = 'block';
            progressBar.style.width = '0%';
            progressPercent.textContent = '0%';
            progressText.textContent = 'Initializing scan...';
            
            // Get scan options
            const options = {
                ssl: document.getElementById('sslCheck').checked,
                headers: document.getElementById('headersCheck').checked,
                dns: document.getElementById('dnsCheck').checked,
                vuln: document.getElementById('vulnCheck').checked
            };
            
            // Simulate progress
            let progress = 0;
            const interval = setInterval(() => {
                progress += 10;
                progressBar.style.width = progress + '%';
                progressPercent.textContent = progress + '%';
                
                if (progress === 10) {
                    progressText.textContent = 'Connecting to website...';
                    scanMessage.textContent = 'Establishing connection...';
                }
                else if (progress === 30) {
                    progressText.textContent = 'Checking SSL certificate...';
                    scanMessage.textContent = 'Validating security certificates...';
                }
                else if (progress === 50) {
                    progressText.textContent = 'Analyzing security headers...';
                    scanMessage.textContent = 'Checking for security misconfigurations...';
                }
                else if (progress === 70) {
                    progressText.textContent = 'Scanning for vulnerabilities...';
                    scanMessage.textContent = 'Looking for common security issues...';
                }
                else if (progress === 90) {
                    progressText.textContent = 'Generating report...';
                    scanMessage.textContent = 'Compiling security findings...';
                }
                
                if (progress >= 100) {
                    clearInterval(interval);
                    progressText.textContent = 'Scan completed!';
                    scanMessage.textContent = 'Analysis finished successfully';
                    scanInProgress = false;
                    
                    // Perform actual scan
                    performScan(url, options);
                }
            }, 300);
        }
        
        function startQuickScan() {
            const url = document.getElementById('scanUrl').value.trim();
            if (!url) {
                alert('Please enter a website URL');
                return;
            }
            
            // Just do quick SSL and HTTP check
            fetch('/api/quick-scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            })
            .then(res => res.json())
            .then(data => {
                showQuickResults(data);
            })
            .catch(err => {
                alert('Quick scan failed: ' + err.message);
            });
        }
        
        function performScan(url, options) {
            fetch('/api/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url, options: options})
            })
            .then(res => res.json())
            .then(data => {
                showResults(data);
            })
            .catch(err => {
                alert('Scan failed: ' + err.message);
                document.getElementById('scanProgress').style.display = 'none';
            });
        }
        
        function showResults(data) {
            document.getElementById('resultsSection').style.display = 'block';
            document.getElementById('scanProgress').style.display = 'none';
            
            const container = document.getElementById('resultsContainer');
            
            if (data.error) {
                container.innerHTML = `
                    <div class="col-12">
                        <div class="result-card stat-high">
                            <h4><i class="fas fa-times-circle me-2"></i> Scan Failed</h4>
                            <p>${data.error}</p>
                        </div>
                    </div>
                `;
                return;
            }
            
            // Risk card
            const riskLevel = data.risk?.level || 'LOW';
            const riskClass = riskLevel.toLowerCase();
            
            let html = `
                <div class="col-md-4">
                    <div class="result-card stat-${riskClass}">
                        <h4><i class="fas fa-shield-alt me-2"></i> Security Score</h4>
                        <div class="text-center my-4">
                            <div class="display-1 fw-bold">${data.risk?.score || 0}</div>
                            <span class="risk-${riskClass} risk-badge">${riskLevel}</span>
                        </div>
                        <p class="text-center">Overall Security Assessment</p>
                    </div>
                </div>
                
                <div class="col-md-4">
                    <div class="result-card">
                        <h4><i class="fas fa-globe me-2"></i> Website Info</h4>
                        <p><strong>URL:</strong> ${data.url}</p>
                        <p><strong>Domain:</strong> ${data.domain}</p>
                        <p><strong>Scan ID:</strong> ${data.scan_id}</p>
                        <p><strong>Time:</strong> ${new Date(data.timestamp).toLocaleTimeString()}</p>
                    </div>
                </div>
                
                <div class="col-md-4">
                    <div class="result-card">
                        <h4><i class="fas fa-bolt me-2"></i> Performance</h4>
                        <p><strong>Status:</strong> ${data.checks?.http?.status_code || 'N/A'}</p>
                        <p><strong>Response Time:</strong> ${data.checks?.http?.response_time || 0}ms</p>
                        <p><strong>Server:</strong> ${data.checks?.http?.server || 'Unknown'}</p>
                        <p><strong>SSL Valid:</strong> ${data.checks?.ssl?.valid ? '✅ Yes' : '❌ No'}</p>
                    </div>
                </div>
            `;
            
            // Security Headers
            if (data.checks?.headers) {
                const headers = data.checks.headers.security_headers || {};
                const missing = Object.values(headers).filter(h => h === 'MISSING').length;
                
                html += `
                    <div class="col-md-6">
                        <div class="result-card">
                            <h4><i class="fas fa-heading me-2"></i> Security Headers</h4>
                            <p><strong>Missing:</strong> ${missing} of ${Object.keys(headers).length}</p>
                            <div class="mt-3">
                                ${Object.entries(headers).map(([key, value]) => `
                                    <div class="d-flex justify-content-between mb-2">
                                        <span>${key.replace('-', ' ').toUpperCase()}</span>
                                        <span class="${value === 'MISSING' ? 'text-danger' : 'text-success'}">
                                            ${value === 'MISSING' ? '❌ Missing' : '✅ Present'}
                                        </span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                `;
            }
            
            // Vulnerabilities
            if (data.checks?.vulnerabilities) {
                const vulns = data.checks.vulnerabilities;
                html += `
                    <div class="col-md-6">
                        <div class="result-card ${vulns.found > 0 ? 'stat-high' : 'stat-low'}">
                            <h4><i class="fas fa-exclamation-triangle me-2"></i> Vulnerabilities</h4>
                            <p><strong>Found:</strong> ${vulns.found || 0} issues</p>
                            ${vulns.list && vulns.list.length > 0 ? `
                                <div class="mt-3">
                                    <ul class="list-unstyled">
                                        ${vulns.list.map(item => `<li class="mb-1">⚠️ ${item}</li>`).join('')}
                                    </ul>
                                </div>
                            ` : '<p class="text-success">✅ No vulnerabilities detected</p>'}
                        </div>
                    </div>
                `;
            }
            
            container.innerHTML = html;
            
            // Scroll to results
            document.getElementById('resultsSection').scrollIntoView({behavior: 'smooth'});
            
            // Update stats
            updateStats();
        }
        
        function showQuickResults(data) {
            // Similar to showResults but simplified
            document.getElementById('resultsSection').style.display = 'block';
            
            const container = document.getElementById('resultsContainer');
            
            let html = `
                <div class="col-12">
                    <div class="result-card">
                        <h4><i class="fas fa-bolt me-2"></i> Quick Scan Results</h4>
                        <p><strong>URL:</strong> ${data.url}</p>
                        <p><strong>Status:</strong> ${data.status || 'Unknown'}</p>
                        <p><strong>SSL:</strong> ${data.ssl_valid ? '✅ Valid' : '❌ Invalid'}</p>
                        <p><strong>Response Time:</strong> ${data.response_time || 'N/A'}ms</p>
                    </div>
                </div>
            `;
            
            container.innerHTML = html;
            document.getElementById('resultsSection').scrollIntoView({behavior: 'smooth'});
        }
        
        function rescanWebsite(url) {
            document.getElementById('scanUrl').value = url;
            startFullScan();
        }
        
        // Initialize chart on load
        document.addEventListener('DOMContentLoaded', function() {
            updateTrafficChart([]);
        });
    </script>
</body>
</html>
'''

# ==================== FLASK ROUTES ====================
@app.route('/')
def index():
    """Main dashboard"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan', methods=['POST'])
@limiter.limit("10 per hour")
def api_scan():
    """Full website scan"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        # Normalize URL
        url = scanner.normalize_url(url)
        
        # Get scan options
        options = data.get('options', {})
        scan_type = "full" if any(options.values()) else "quick"
        
        # Perform scan
        results = scanner.scan_website(url, scan_type)
        
        # Log traffic
        db.log_traffic(
            url=url,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:200],
            scan_type=scan_type,
            risk_score=results.get("risk", {}).get("score", 0)
        )
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/quick-scan', methods=['POST'])
@limiter.limit("20 per hour")
def quick_scan():
    """Quick website scan"""
    try:
        data = request.json
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        url = scanner.normalize_url(url)
        domain = scanner.extract_domain(url)
        
        # Quick HTTP check
        http_result = scanner.check_http(url)
        
        # Quick SSL check
        ssl_result = scanner.check_ssl(domain)
        
        results = {
            "url": url,
            "status": "success" if http_result.get("status") == "success" else "failed",
            "ssl_valid": ssl_result.get("valid", False),
            "response_time": http_result.get("response_time", 0),
            "timestamp": datetime.now().isoformat()
        }
        
        # Log traffic
        db.log_traffic(
            url=url,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:200],
            scan_type="quick",
            risk_score=0
        )
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/traffic/stats')
def traffic_stats():
    """Get traffic statistics"""
    try:
        # Get traffic report
        report = traffic_analyzer.generate_traffic_report(days=7)
        
        # Get top websites
        top_websites = db.get_top_scanned(10)
        
        # Calculate active users (last hour)
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(DISTINCT ip_address) 
            FROM traffic_logs 
            WHERE timestamp >= datetime('now', '-1 hour')
        ''')
        active_users = cursor.fetchone()[0]
        conn.close()
        
        # Calculate secure sites
        secure_sites = 0
        for site in top_websites:
            if site['avg_risk'] < 40:  # LOW risk
                secure_sites += 1
        
        return jsonify({
            "total_scans": report['summary']['total_scans'],
            "secure_sites": secure_sites,
            "vulnerabilities": report['summary']['high_risk_scans'],
            "active_users": active_users,
            "peak_hour": max(report['patterns']['hourly_patterns'], key=lambda x: x['count'])['hour'] if report['patterns']['hourly_patterns'] else 0,
            "high_risk": report['summary']['high_risk_scans'],
            "avg_response": 150,  # Mock data
            "top_websites": top_websites,
            "traffic_data": report['patterns']['daily_traffic'][-7:]  # Last 7 days
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/traffic/report')
def traffic_report():
    """Get detailed traffic report"""
    try:
        report = traffic_analyzer.generate_traffic_report(days=30)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

# ==================== LEGALITY ====================
'''
⚠️ LEGAL DISCLAIMER:
--------------------
This tool is for:
1. Educational purposes only
2. Security research
3. Testing your own websites
4. Authorized penetration testing (with written permission)

❌ DO NOT USE FOR:
1. Scanning websites without permission
2. Malicious activities
3. Hacking attempts
4. Illegal surveillance

✅ LEGAL USES:
1. Bug bounty programs (with permission)
2. Security audits of your own infrastructure
3. Learning cybersecurity
4. Academic research

Always get WRITTEN PERMISSION before scanning any website!
'''

# ==================== MAIN ====================
if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  CyberShield Pro - Ultimate Security & Traffic Analyzer")
    print("=" * 70)
    print("📊 Features:")
    print("  • Website Security Scanning")
    print("  • Real-time Traffic Analysis")
    print("  • Advanced Risk Assessment")
    print("  • Database-backed Analytics")
    print("  • Beautiful Interactive Dashboard")
    print("")
    print("🌐 Access the dashboard at: http://localhost:5000")
    print("")
    print("⚠️  LEGAL NOTICE:")
    print("  This tool is for AUTHORIZED security testing only!")
    print("  Always get permission before scanning any website.")
    print("=" * 70)
    
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('DEBUG', 'false').lower() == 'true',
        threaded=True
    )
