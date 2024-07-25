from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)

# Add your VirusTotal API key here
VIRUSTOTAL_API_KEY = 'VIRUSTOTAL_API_KEY'

def get_ip_details(ip):
    response = requests.get(f'http://ipinfo.io/{ip}/json')
    details = response.json()

    # Check the IP reputation with VirusTotal
    vt_response = requests.get(
        f'https://www.virustotal.com/vtapi/v2/ip-address/report',
        params={'ip': ip, 'apikey': VIRUSTOTAL_API_KEY}
    )
    vt_data = vt_response.json()
    details['virustotal'] = vt_data
    return details

def rate_ip(ip_details):
    score = 0
    
    # Example criteria for rating
    if ip_details.get('country') == 'US':
        score += 1
    if 'Google' in ip_details.get('org', ''):
        score += 1
    if 'Integrated Telecom Co. Ltd' in ip_details.get('org', ''):
        score -= 1  # Example of penalizing specific ISP
    
    # Placeholder for checking known malicious IPs
    known_malicious_ips = ['192.0.2.1', '203.0.113.1']
    if ip_details.get('ip') in known_malicious_ips:
        score -= 5
    
    # Add criteria for specific regions
    high_risk_countries = ['CN', 'RU']
    if ip_details.get('country') in high_risk_countries:
        score -= 2
    
    # Check for other specific organizations
    suspicious_orgs = ['AS12345 Malicious ISP', 'AS67890 Bad Actor', 'Tencent Building']
    if any(org in ip_details.get('org', '') for org in suspicious_orgs):
        score -= 3
    
    # Check VirusTotal data
    vt_data = ip_details.get('virustotal', {})
    detected_urls = vt_data.get('detected_urls', [])
    if detected_urls:
        score -= 2 * len(detected_urls)
    
    # Example additional checks using VirusTotal data
    if vt_data.get('malicious_votes', 0) > 0:
        score -= vt_data['malicious_votes']
    if vt_data.get('suspicious_votes', 0) > 0:
        score -= vt_data['suspicious_votes']
    
    # Check for resolutions
    resolutions = vt_data.get('resolutions', [])
    if len(resolutions) > 1:
        score -= len(resolutions)
    
    # Determine qualitative rating
    qualitative_rating = "Good" if score >= 0 else "Bad"
    
    return score, qualitative_rating

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/track', methods=['POST'])
def track_ip():
    ip = request.form['ip']
    details = get_ip_details(ip)
    score, qualitative_rating = rate_ip(details)
    return jsonify({'details': details, 'score': score, 'rating': qualitative_rating})

if __name__ == '__main__':
    app.run(debug=True)
