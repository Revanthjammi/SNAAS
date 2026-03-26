# app.py - Fixed version with proper JSON serialization
import os
import hashlib
import json
from datetime import datetime
from decimal import Decimal
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import plotly.graph_objs as go
import plotly.utils
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import io
from collections import defaultdict
import ast 
# Try importing scapy
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ARP, DNS, DNSQR, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_analysis.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('instance', exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Custom JSON encoder for Decimal
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    analyses = db.relationship('Analysis', backref='user', lazy=True)

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    file_hash = db.Column(db.String(64))
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    threats_detected = db.Column(db.Integer, default=0)
    analysis_results = db.Column(db.Text)
    packet_count = db.Column(db.Integer, default=0)
    protocol_stats = db.Column(db.Text, default='{}')

class ThreatDetection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'), nullable=False)
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    packet_info = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def convert_to_serializable(obj):
    """Convert non-serializable objects to serializable format"""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_to_serializable(value) for key, value in obj.items()}
    return obj

def analyze_packets_detailed(packets):
    """Comprehensive packet analysis with proper serialization"""
    stats = {
        'total_packets': len(packets),
        'protocols': {
            'TCP': 0,
            'UDP': 0,
            'ARP': 0,
            'DNS': 0,
            'ICMP': 0,
            'Other': 0
        },
        'ip_stats': {},
        'port_stats': {},
        'packet_sizes': [],
        'timestamps': [],
        'top_talkers': []
    }
    
    threats = []
    
    if not SCAPY_AVAILABLE:
        return stats, threats
    
    # Use regular dict instead of defaultdict for JSON serialization
    ip_stats = {}
    port_stats = {}
    arp_mac_mapping = {}
    dns_responses = {}
    syn_count = {}
    
    for idx, packet in enumerate(packets):
        try:
            # Convert Decimal to float for timestamps
            if hasattr(packet, 'time'):
                timestamp = float(packet.time) if isinstance(packet.time, Decimal) else packet.time
                stats['timestamps'].append(timestamp)
            
            packet_size = len(packet)
            stats['packet_sizes'].append(packet_size)
            
            # Protocol classification
            if TCP in packet:
                stats['protocols']['TCP'] += 1
                
                # SYN flood detection
                if packet[TCP].flags == 0x02:
                    src_ip = packet[IP].src if IP in packet else 'Unknown'
                    syn_count[src_ip] = syn_count.get(src_ip, 0) + 1
                    if syn_count[src_ip] > 100:
                        threats.append({
                            'type': 'SYN Flood',
                            'severity': 'Medium',
                            'description': f'High number of SYN packets from {src_ip}',
                            'packet_info': f'{syn_count[src_ip]} SYNs detected',
                            'packet_index': idx
                        })
            
            elif UDP in packet:
                stats['protocols']['UDP'] += 1
            
            elif ARP in packet:
                stats['protocols']['ARP'] += 1
                arp = packet[ARP]
                key = f"{arp.psrc}"
                
                # ARP spoofing detection
                if key in arp_mac_mapping:
                    if arp_mac_mapping[key] != arp.hwsrc:
                        threats.append({
                            'type': 'ARP Spoofing',
                            'severity': 'High',
                            'description': f'Duplicate ARP reply for IP {arp.psrc}',
                            'packet_info': f'MAC {arp.hwsrc} claims to be {arp.psrc}',
                            'packet_index': idx
                        })
                else:
                    arp_mac_mapping[key] = arp.hwsrc
            
            elif DNS in packet:
                stats['protocols']['DNS'] += 1
                
                # DNS Spoofing detection
                if packet[DNS].qr == 1:
                    if DNSQR in packet:
                        query_name = packet[DNSQR].qname
                        if isinstance(query_name, bytes):
                            query_name = query_name.decode('utf-8', errors='ignore')
                        
                        if packet.haslayer('DNSRR'):
                            for i in range(packet[DNS].ancount):
                                try:
                                    rr = packet[DNS].an[i]
                                    if rr.type == 1:
                                        ip = rr.rdata
                                        if query_name in dns_responses:
                                            if dns_responses[query_name] != ip:
                                                threats.append({
                                                    'type': 'DNS Spoofing',
                                                    'severity': 'High',
                                                    'description': f'Conflicting DNS responses for {query_name}',
                                                    'packet_info': f'{query_name} -> {ip}',
                                                    'packet_index': idx
                                                })
                                        else:
                                            dns_responses[query_name] = ip
                                except:
                                    pass
            
            elif ICMP in packet:
                stats['protocols']['ICMP'] += 1
            
            else:
                stats['protocols']['Other'] += 1
            
            # IP statistics
            if IP in packet:
                src_ip = str(packet[IP].src)
                dst_ip = str(packet[IP].dst)
                
                if src_ip not in ip_stats:
                    ip_stats[src_ip] = {'sent': 0, 'received': 0}
                if dst_ip not in ip_stats:
                    ip_stats[dst_ip] = {'sent': 0, 'received': 0}
                
                ip_stats[src_ip]['sent'] += 1
                ip_stats[dst_ip]['received'] += 1
            
            # Port statistics
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                port_stats[f"TCP:{src_port}"] = port_stats.get(f"TCP:{src_port}", 0) + 1
                port_stats[f"TCP:{dst_port}"] = port_stats.get(f"TCP:{dst_port}", 0) + 1
            
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                port_stats[f"UDP:{src_port}"] = port_stats.get(f"UDP:{src_port}", 0) + 1
                port_stats[f"UDP:{dst_port}"] = port_stats.get(f"UDP:{dst_port}", 0) + 1
            
            # Suspicious packet detection
            if packet_size > 1500:
                threats.append({
                    'type': 'Suspicious Packet',
                    'severity': 'Low',
                    'description': 'Oversized packet detected',
                    'packet_info': f'Size: {packet_size} bytes',
                    'packet_index': idx
                })
                
        except Exception as e:
            print(f"Error processing packet {idx}: {e}")
            continue
    
    # Convert ip_stats to regular dict and get top talkers
    stats['ip_stats'] = ip_stats
    stats['port_stats'] = port_stats
    
    # Get top talkers
    if ip_stats:
        top_talkers = sorted(ip_stats.items(), 
                            key=lambda x: x[1]['sent'] + x[1]['received'], 
                            reverse=True)[:10]
        stats['top_talkers'] = [{'ip': ip, 'sent': data['sent'], 'received': data['received']} 
                                for ip, data in top_talkers]
    
    return stats, threats

def create_advanced_visualizations(stats):
    """Create visualizations with proper JSON serialization"""
    visualizations = {}
    
    try:
        if stats and stats.get('protocols'):
            # Protocol Pie Chart
            proto_pie = go.Pie(
                labels=list(stats['protocols'].keys()),
                values=list(stats['protocols'].values()),
                hole=0.3,
                textinfo='label+percent',
                marker=dict(colors=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD'])
            )
            visualizations['protocol_pie'] = json.dumps(proto_pie, cls=plotly.utils.PlotlyJSONEncoder)
            
            # Protocol Bar Chart
            proto_bar = go.Bar(
                x=list(stats['protocols'].keys()),
                y=list(stats['protocols'].values()),
                marker=dict(color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD']),
                text=list(stats['protocols'].values()),
                textposition='auto'
            )
            visualizations['protocol_bar'] = json.dumps(proto_bar, cls=plotly.utils.PlotlyJSONEncoder)
        
        # Timeline Chart
        if stats.get('timestamps') and stats.get('packet_sizes'):
            timeline = go.Scatter(
                x=stats['timestamps'],
                y=stats['packet_sizes'],
                mode='lines+markers',
                marker=dict(size=4, color='#FF6B6B'),
                line=dict(color='#4ECDC4', width=2)
            )
            visualizations['timeline'] = json.dumps(timeline, cls=plotly.utils.PlotlyJSONEncoder)
        
        # Top Talkers Chart
        if stats.get('top_talkers'):
            top_ips = [talker['ip'] for talker in stats['top_talkers'][:5]]
            total_packets = [talker['sent'] + talker['received'] for talker in stats['top_talkers'][:5]]
            talkers = go.Bar(
                x=top_ips,
                y=total_packets,
                marker=dict(color='#45B7D1'),
                text=total_packets,
                textposition='auto'
            )
            visualizations['top_talkers'] = json.dumps(talkers, cls=plotly.utils.PlotlyJSONEncoder)
        
        # Top Ports Chart
        if stats.get('port_stats'):
            top_ports = sorted(stats['port_stats'].items(), key=lambda x: x[1], reverse=True)[:10]
            if top_ports:
                port_names = [port for port, count in top_ports]
                port_counts = [count for port, count in top_ports]
                ports = go.Bar(
                    x=port_names,
                    y=port_counts,
                    marker=dict(color='#96CEB4'),
                    text=port_counts,
                    textposition='auto'
                )
                visualizations['top_ports'] = json.dumps(ports, cls=plotly.utils.PlotlyJSONEncoder)
    
    except Exception as e:
        print(f"Error creating visualizations: {e}")
    
    return visualizations

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Welcome back! 🎉', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.upload_time.desc()).all()
    return render_template('dashboard.html', analyses=analyses)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'pcap_file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['pcap_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            
            file_hash = calculate_file_hash(filepath)
            
            try:
                if SCAPY_AVAILABLE:
                    packets = rdpcap(filepath)
                    stats, threats = analyze_packets_detailed(packets)
                    
                    # Convert stats to JSON serializable format
                    stats_serializable = convert_to_serializable(stats)
                    
                    analysis = Analysis(
                        filename=filename,
                        file_hash=file_hash,
                        user_id=current_user.id,
                        threats_detected=len(threats),
                        packet_count=stats['total_packets'],
                        analysis_results=json.dumps(threats, cls=DecimalEncoder),
                        protocol_stats=json.dumps(stats_serializable, cls=DecimalEncoder)
                    )
                    db.session.add(analysis)
                    db.session.flush()
                    
                    for threat in threats:
                        threat_record = ThreatDetection(
                            analysis_id=analysis.id,
                            threat_type=threat['type'],
                            severity=threat['severity'],
                            description=threat['description'],
                            packet_info=threat['packet_info']
                        )
                        db.session.add(threat_record)
                    
                    db.session.commit()
                    
                    flash(f'✅ File uploaded successfully! Detected {len(threats)} threats.', 'success')
                    return redirect(url_for('analyze', analysis_id=analysis.id))
                else:
                    flash('Scapy is not installed. Please install scapy for PCAP analysis.', 'error')
                    
            except Exception as e:
                flash(f'Error analyzing file: {str(e)}', 'error')
                if os.path.exists(filepath):
                    os.remove(filepath)
                return redirect(request.url)
        else:
            flash('Please upload a valid .pcap or .pcapng file', 'error')
            return redirect(request.url)
    
    return render_template('upload.html')

@app.route('/analyze/<int:analysis_id>')
@login_required
def analyze(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Load analysis data with error handling
    stats = {}
    if analysis.protocol_stats:
        try:
            stats = json.loads(analysis.protocol_stats)
        except json.JSONDecodeError:
            stats = {}
    
    threats = ThreatDetection.query.filter_by(analysis_id=analysis_id).all()
    visualizations = create_advanced_visualizations(stats)
    protocol_stats = stats.get('protocols', {'TCP': 0, 'UDP': 0, 'ARP': 0, 'DNS': 0, 'ICMP': 0, 'Other': 0})
    
    return render_template('analyze.html',
                         analysis=analysis,
                         stats=stats,
                         protocol_stats=protocol_stats,
                         threats=threats,
                         visualizations=visualizations,
                         packet_count=analysis.packet_count)

@app.route('/generate_report/<int:analysis_id>')
@login_required
def generate_report(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Load stats with error handling
    stats = {}
    if analysis.protocol_stats:
        try:
            stats = json.loads(analysis.protocol_stats)
        except json.JSONDecodeError:
            stats = {}
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], 
                                 fontSize=24, textColor=colors.HexColor('#667eea'), spaceAfter=30)
    story.append(Paragraph("Network Security Analysis Report", title_style))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph(f"<b>Analysis ID:</b> {analysis.id}", styles['Normal']))
    story.append(Paragraph(f"<b>Filename:</b> {analysis.filename}", styles['Normal']))
    story.append(Paragraph(f"<b>Upload Time:</b> {analysis.upload_time}", styles['Normal']))
    story.append(Paragraph(f"<b>User:</b> {analysis.user.username}", styles['Normal']))
    story.append(Paragraph(f"<b>Total Packets:</b> {analysis.packet_count:,}", styles['Normal']))
    story.append(Paragraph(f"<b>Threats Detected:</b> {analysis.threats_detected}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Protocol Statistics
    if stats and 'protocols' in stats:
        story.append(Paragraph("Protocol Statistics", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        proto_data = [['Protocol', 'Count', 'Percentage']]
        total = sum(stats['protocols'].values())
        for proto, count in stats['protocols'].items():
            percentage = (count / total * 100) if total > 0 else 0
            proto_data.append([proto, str(count), f"{percentage:.1f}%"])
        
        proto_table = Table(proto_data, colWidths=[100, 100, 100])
        proto_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(proto_table)
    
    story.append(Spacer(1, 20))
    
    # Threats Section
    story.append(Paragraph("Detected Threats", styles['Heading2']))
    story.append(Spacer(1, 12))
    
    threats = ThreatDetection.query.filter_by(analysis_id=analysis_id).all()
    
    if threats:
        threat_data = [['Threat Type', 'Severity', 'Description', 'Packet Info']]
        for threat in threats:
            threat_data.append([
                threat.threat_type,
                threat.severity,
                threat.description,
                threat.packet_info[:50] + '...' if len(threat.packet_info) > 50 else threat.packet_info
            ])
        
        threat_table = Table(threat_data, colWidths=[100, 60, 200, 150])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f56565')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(threat_table)
    else:
        story.append(Paragraph("No threats detected in this analysis.", styles['Normal']))
    
    # Top Talkers
    if stats and 'top_talkers' in stats and stats['top_talkers']:
        story.append(Spacer(1, 20))
        story.append(Paragraph("Top Network Talkers", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        talker_data = [['IP Address', 'Packets Sent', 'Packets Received', 'Total']]
        for talker in stats['top_talkers'][:10]:
            talker_data.append([
                talker['ip'],
                str(talker['sent']),
                str(talker['received']),
                str(talker['sent'] + talker['received'])
            ])
        
        talker_table = Table(talker_data, colWidths=[120, 80, 80, 80])
        talker_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#48bb78')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(talker_table)
    
    story.append(Spacer(1, 20))
    
    # Recommendations
    story.append(Paragraph("Security Recommendations", styles['Heading2']))
    story.append(Spacer(1, 12))
    
    recommendations = [
        "• Regularly monitor network traffic for suspicious patterns",
        "• Implement ARP spoofing detection mechanisms",
        "• Use DNSSEC to prevent DNS spoofing attacks",
        "• Deploy intrusion detection systems (IDS)",
        "• Conduct regular security audits",
        "• Monitor unusual port activity and SYN flood attempts"
    ]
    
    for rec in recommendations:
        story.append(Paragraph(rec, styles['Normal']))
        story.append(Spacer(1, 6))
    
    doc.build(story)
    buffer.seek(0)
    
    return send_file(buffer, as_attachment=True, 
                    download_name=f'security_report_{analysis_id}.pdf', 
                    mimetype='application/pdf')

@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        try:
            return json.loads(value)
        except:
            return []
    return []

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create demo user if not exists
        if not User.query.filter_by(username='demo').first():
            demo_user = User(
                username='demo',
                password_hash=generate_password_hash('demo123')
            )
            db.session.add(demo_user)
            db.session.commit()
            print("✓ Demo user created: demo / demo123")
    
    print("\n✓ Application is running!")
    print("✓ Access at: http://localhost:5000")
    print("✓ Login with: demo / demo123")
    app.run(debug=True)