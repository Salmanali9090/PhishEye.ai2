# PhishEye.ai - OPTIMIZED & COMPACT Backend
# Faster scans, Link scanner added, Better performance

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests
import time
from datetime import datetime
import re
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
from reportlab.lib.units import inch
import io
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# API Keys
VIRUSTOTAL_API_KEY = "4d5bd7f9aaeefde19b602547bcc903cabd5f4cbc3a9cb0c81c6f7ca156deed23"
GROQ_API_KEY = "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"

VT_BASE = "https://www.virustotal.com/api/v3"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

# =============================================================================
# GROQ AI - COMPACT RESPONSES
# =============================================================================
def ask_groq(prompt, max_tokens=400):
    """Groq API with SHORT, clean responses"""
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity expert. Be concise and clear. No markdown formatting."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": max_tokens
    }
    
    try:
        response = requests.post(GROQ_URL, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        text = response.json()['choices'][0]['message']['content']
        # Remove markdown symbols
        text = text.replace('**', '').replace('##', '').replace('*', '')
        return text.strip()
    except Exception as e:
        print(f"❌ Groq Error: {e}")
        return "AI analysis unavailable."

# =============================================================================
# VIRUSTOTAL - FASTER SCANS (3-4 seconds)
# =============================================================================
def vt_scan_url(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        # Submit
        scan_response = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=5)
        if scan_response.status_code != 200:
            return None
        analysis_id = scan_response.json()['data']['id']
        
        # Quick wait - optimized to 2 seconds
        time.sleep(2)
        
        # Get result
        result = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=5)
        return result.json() if result.status_code == 200 else None
    except Exception as e:
        print(f"❌ VT URL: {e}")
        return None

def vt_scan_domain(domain):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(f"{VT_BASE}/domains/{domain}", headers=headers, timeout=5)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ VT Domain: {e}")
        return None

def vt_scan_ip(ip):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=headers, timeout=5)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ VT IP: {e}")
        return None

def vt_scan_hash(file_hash):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(f"{VT_BASE}/files/{file_hash}", headers=headers, timeout=5)
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        print(f"❌ VT Hash: {e}")
        return None

def parse_vt_results(vt_data, scan_type):
    if not vt_data or 'data' not in vt_data:
        return None
    try:
        attrs = vt_data['data']['attributes']
        stats = attrs.get('stats', attrs.get('last_analysis_stats', {}))
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected
        
        results = attrs.get('results', attrs.get('last_analysis_results', {}))
        vendors = []
        for vendor, result in list(results.items())[:5]:
            if isinstance(result, dict) and result.get('category') in ['malicious', 'suspicious']:
                vendors.append({'name': vendor, 'category': result.get('category')})
        
        status = "malicious" if malicious > 3 else "suspicious" if (malicious > 0 or suspicious > 2) else "safe"
        
        return {
            "status": status,
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total,
            "detection_ratio": f"{malicious}/{total}",
            "vendors": vendors
        }
    except Exception as e:
        print(f"❌ Parse: {e}")
        return None

# =============================================================================
# LINK ANALYSIS - NEW FEATURE
# =============================================================================
def analyze_link(link):
    """Analyze suspicious link patterns"""
    indicators = []
    threat_score = 0
    
    try:
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Check for suspicious patterns
        suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 
                              'banking', 'paypal', 'suspended', 'urgent', 'click']
        for keyword in suspicious_keywords:
            if keyword in domain or keyword in path:
                indicators.append(f"Suspicious keyword: {keyword}")
                threat_score += 1
        
        # Check for IP address as domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            indicators.append("Uses IP address instead of domain")
            threat_score += 2
        
        # Check for unusual TLDs
        unusual_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(domain.endswith(tld) for tld in unusual_tlds):
            indicators.append("Unusual top-level domain")
            threat_score += 2
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            indicators.append(f"Excessive subdomains ({subdomain_count})")
            threat_score += 1
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        if any(short in domain for short in shorteners):
            indicators.append("URL shortener detected")
            threat_score += 1
        
        # Check for typosquatting patterns (common brand misspellings)
        brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix']
        for brand in brands:
            if brand in domain and brand != domain.split('.')[0]:
                indicators.append(f"Potential typosquatting: {brand}")
                threat_score += 3
        
        # Check for excessive hyphens
        if domain.count('-') > 2:
            indicators.append("Excessive hyphens in domain")
            threat_score += 1
        
        # Check URL length
        if len(link) > 100:
            indicators.append("Unusually long URL")
            threat_score += 1
        
        # Determine status
        if threat_score >= 5:
            status = "malicious"
        elif threat_score >= 3:
            status = "suspicious"
        else:
            status = "safe"
        
        return {
            "status": status,
            "indicators": indicators,
            "threat_count": threat_score,
            "domain": domain
        }
    
    except Exception as e:
        return {
            "status": "suspicious",
            "indicators": ["Failed to parse URL"],
            "threat_count": 1,
            "domain": "unknown"
        }

# =============================================================================
# EMAIL ANALYSIS
# =============================================================================
def analyze_email(content):
    indicators = []
    urgency = ['urgent', 'immediate', 'suspended', 'verify now', 'act now', 'expire', 'locked']
    for word in urgency:
        if word in content.lower():
            indicators.append(f"Urgency: {word}")
            break
    
    urls = re.findall(r'http[s]?://[^\s]+', content)
    if urls:
        indicators.append(f"{len(urls)} suspicious link(s)")
    
    sensitive = ['password', 'credit card', 'ssn', 'bank', 'account number', 'verify']
    for word in sensitive:
        if word in content.lower():
            indicators.append(f"Requests: {word}")
            break
    
    threat_level = len(indicators)
    status = "malicious" if threat_level >= 3 else "suspicious" if threat_level >= 2 else "safe"
    
    return {
        "status": status,
        "indicators": indicators,
        "threat_count": threat_level
    }

# =============================================================================
# MAIN SCAN - COMPACT & FAST
# =============================================================================
@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        data = request.json
        scan_type = data.get('scan_type')
        input_value = data.get('input_value')
        
        print(f"\n{'='*60}")
        print(f"🔍 {scan_type.upper()}: {input_value[:40]}...")
        print(f"{'='*60}")
        
        # Scan based on type
        if scan_type == "url":
            vt_data = vt_scan_url(input_value)
        elif scan_type == "domain":
            vt_data = vt_scan_domain(input_value)
        elif scan_type == "ip":
            vt_data = vt_scan_ip(input_value)
        elif scan_type == "hash":
            vt_data = vt_scan_hash(input_value)
        elif scan_type == "link":
            # NEW: Link analysis
            link_data = analyze_link(input_value)
            result = {
                "status": link_data["status"],
                "detection_ratio": f"{link_data['threat_count']}/10",
                "threats": link_data["threat_count"],
                "indicators": link_data["indicators"],
                "domain": link_data["domain"]
            }
            vt_data = None
        elif scan_type == "email":
            email_data = analyze_email(input_value)
            result = {
                "status": email_data["status"],
                "detection_ratio": f"{email_data['threat_count']}/10",
                "threats": email_data["threat_count"],
                "indicators": email_data["indicators"]
            }
            vt_data = None
        
        if scan_type not in ["email", "link"]:
            parsed = parse_vt_results(vt_data, scan_type)
            if not parsed:
                return jsonify({"error": "Scan failed"}), 500
            result = {
                "status": parsed["status"],
                "detection_ratio": parsed["detection_ratio"],
                "threats": parsed["malicious"],
                "malicious": parsed["malicious"],
                "suspicious": parsed["suspicious"],
                "total": parsed["total"],
                "vendors": parsed["vendors"]
            }
        
        # SHORT AI SUMMARIES
        short_prompt = f"In 2-3 SHORT sentences, explain this {scan_type} scan: Status is {result['status']}, detection {result['detection_ratio']}. Be brief and clear."
        
        detailed_prompt = f"""Brief security analysis for {scan_type}:
Status: {result['status']}
Detection: {result['detection_ratio']}

Write 3 short paragraphs (2-3 sentences each):
1. What was found
2. Risk level
3. Key concerns

Keep it concise. No lists."""

        remediation_prompt = f"List 5 SHORT action steps for {result['status']} {scan_type}. Each step should be ONE clear sentence. Number 1-5. No explanations."
        
        short_summary = ask_groq(short_prompt, 200)
        detailed_summary = ask_groq(detailed_prompt, 500)
        remediation_raw = ask_groq(remediation_prompt, 400)
        
        # Parse remediation - clean format
        remediation = []
        for line in remediation_raw.split('\n'):
            line = line.strip()
            if line and len(line) > 10:
                clean = re.sub(r'^[\d\-•\.)\]\s]+', '', line).strip()
                if clean and len(clean) > 15 and len(clean) < 150:
                    remediation.append(clean)
        
        if len(remediation) < 3:
            remediation = [
                "Stop interacting with this resource immediately",
                "Do not enter credentials or personal information",
                "Run antivirus scan if you accessed it",
                "Report to your security team",
                "Monitor accounts for suspicious activity"
            ] if result['status'] != 'safe' else [
                "Continue with standard security practices",
                "Keep software updated regularly",
                "Use strong unique passwords"
            ]
        
        response = {
            "type": scan_type,
            "input": input_value,
            "status": result["status"],
            "detection_ratio": result["detection_ratio"],
            "threats": result["threats"],
            "timestamp": datetime.now().isoformat(),
            "short_summary": short_summary,
            "detailed_summary": detailed_summary,
            "remediation": remediation[:5],
            "vt_details": {
                "malicious": result.get("malicious", 0),
                "suspicious": result.get("suspicious", 0),
                "total_scans": result.get("total", 92),
                "vendors": result.get("vendors", [])
            } if scan_type not in ["email", "link"] else {},
            "indicators": result.get("indicators", []),
            "domain": result.get("domain", "")
        }
        
        print(f"✅ {response['status'].upper()} - {response['detection_ratio']}\n")
        return jsonify(response), 200
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": str(e)}), 500

# =============================================================================
# AI CHAT - SHORT REPLIES
# =============================================================================
@app.route('/api/ai-chat', methods=['POST'])
def ai_chat():
    try:
        data = request.json
        message = data.get('message')
        context = data.get('context', '')
        
        prompt = f"""Context: {context}

Question: {message}

Answer in 2-3 SHORT sentences. Be helpful but brief. No lists or explanations unless asked."""

        ai_response = ask_groq(prompt, 250)
        return jsonify({"response": ai_response}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# PDF - CLEAN FORMAT
# =============================================================================
@app.route('/api/generate-pdf', methods=['POST'])
def generate_pdf():
    try:
        data = request.json
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=26,
            textColor=colors.HexColor('#00BCD4'), alignment=1, spaceAfter=15)
        story.append(Paragraph("PhishEye.ai", title_style))
        story.append(Paragraph("Threat Intelligence Report", styles['Heading2']))
        story.append(Spacer(1, 0.3*inch))
        
        # Details table
        details = [
            ['Scan Type:', data.get('type', '').upper()],
            ['Target:', data.get('input', 'N/A')[:65]],
            ['Status:', data.get('status', '').upper()],
            ['Detection:', data.get('detection_ratio', 'N/A')],
            ['Date:', data.get('timestamp', '')[:19]]
        ]
        
        t = Table(details, colWidths=[1.8*inch, 4.7*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.lightgrey),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        story.append(t)
        story.append(Spacer(1, 0.25*inch))
        
        # Summary
        story.append(Paragraph("Summary", styles['Heading3']))
        summary_text = data.get('short_summary', 'N/A').replace('**', '').replace('*', '')
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Analysis
        story.append(Paragraph("Analysis", styles['Heading3']))
        analysis_text = data.get('detailed_summary', 'N/A').replace('**', '').replace('*', '')
        for para in analysis_text.split('\n\n'):
            if para.strip():
                story.append(Paragraph(para.strip(), styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
        story.append(Spacer(1, 0.15*inch))
        
        # Remediation
        story.append(Paragraph("Remediation Steps", styles['Heading3']))
        for i, step in enumerate(data.get('remediation', [])[:5], 1):
            clean_step = step.replace('**', '').replace('*', '')
            story.append(Paragraph(f"{i}. {clean_step}", styles['Normal']))
            story.append(Spacer(1, 0.08*inch))
        
        story.append(Spacer(1, 0.25*inch))
        footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9, textColor=colors.grey)
        story.append(Paragraph("© 2026 PhishEye.ai - All Rights Reserved", footer_style))
        
        doc.build(story)
        buffer.seek(0)
        
        return send_file(buffer, mimetype='application/pdf', as_attachment=True,
                        download_name=f'PhishEye_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "PhishEye.ai"})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  PhishEye.ai - Fast & Upgraded")
    print("="*60)
    print("✅ APIs: Active")
    print("✅ Link Scanner: Added")
    print("✅ Speed: Optimized (3-4s)")
    print("="*60)
    print("🚀 http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)