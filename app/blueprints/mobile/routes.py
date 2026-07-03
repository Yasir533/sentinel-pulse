import os
from flask import render_template, redirect, url_for, request, flash, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app.extensions import db
from app.blueprints.mobile import mobile_bp
from app.models.mobile_security import MobileSubmission, ThreatIntel
from app.services.ai_scam_analyzer import AIScamAnalyzer

def calculate_user_security_score(user_id: int) -> int:
    submissions = MobileSubmission.query.filter_by(user_id=user_id).all()
    if not submissions:
        return 100
    
    deductions = 0
    for sub in submissions:
        if sub.verdict == 'ESCALATE':
            deductions += 25
        elif sub.verdict == 'BLOCK':
            deductions += 15
        elif sub.verdict == 'WARN':
            deductions += 8
        elif sub.verdict == 'QUARANTINE':
            deductions += 4
        else:
            deductions += 1
            
    score = 100 - deductions
    return max(min(score, 100), 15)

@mobile_bp.route('/dashboard')
@login_required
def dashboard():
    # Fetch user's submissions
    submissions = MobileSubmission.query.filter_by(user_id=current_user.id).order_by(MobileSubmission.created_at.desc()).all()
    
    # Calculate metric totals
    total_blocked = MobileSubmission.query.filter(
        MobileSubmission.user_id == current_user.id,
        MobileSubmission.verdict.in_(['BLOCK', 'ESCALATE'])
    ).count()
    
    high_risk_msgs = MobileSubmission.query.filter(
        MobileSubmission.user_id == current_user.id,
        MobileSubmission.submission_type.in_(['sms', 'whatsapp']),
        MobileSubmission.risk_score >= 60
    ).count()
    
    malicious_links = MobileSubmission.query.filter(
        MobileSubmission.user_id == current_user.id,
        MobileSubmission.submission_type == 'url',
        MobileSubmission.risk_score >= 50
    ).count()
    
    unsafe_apks = MobileSubmission.query.filter(
        MobileSubmission.user_id == current_user.id,
        MobileSubmission.submission_type == 'apk',
        MobileSubmission.risk_score >= 50
    ).count()
    
    security_score = calculate_user_security_score(current_user.id)
    
    # Populate default ThreatIntel records if empty for demo purposes
    if ThreatIntel.query.count() == 0:
        try:
            db.session.add_all([
                ThreatIntel(intel_type='domain', intel_value='secure-hdfc-kyc.com', classification='Fake Bank Scam'),
                ThreatIntel(intel_type='phone', intel_value='+18005550199', classification='Impersonation Campaign'),
                ThreatIntel(intel_type='url', intel_value='http://fedex-parcel-charge.net/login', classification='Fake Courier Phishing'),
                ThreatIntel(intel_type='email', intel_value='service@paypal-claims-support.com', classification='Credential Phishing'),
                ThreatIntel(intel_type='hash', intel_value='8519962a9c13cfc1d1a646c2d829962a229a4aef5cfc8a1cfd56d11a2f2bb3a9', classification='Trojan Horse APK')
            ])
            db.session.commit()
        except Exception:
            db.session.rollback()

    recent_activity = submissions[:6]
    
    # Simple risk trend mock data
    trend_labels = ['Week 1', 'Week 2', 'Week 3', 'Week 4']
    trend_values = [85, 90, 80, security_score]
    
    return render_template(
        'mobile/dashboard.html',
        security_score=security_score,
        total_blocked=total_blocked,
        high_risk_msgs=high_risk_msgs,
        malicious_links=malicious_links,
        unsafe_apks=unsafe_apks,
        recent_activity=recent_activity,
        trend_labels=trend_labels,
        trend_values=trend_values
    )

@mobile_bp.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_threat():
    if request.method == 'POST':
        submission_type = request.form.get('submission_type')
        content = request.form.get('content')
        sender = request.form.get('sender', '')
        sha256 = request.form.get('sha256', '')
        filename = request.form.get('filename', '')
        description = request.form.get('description', '')
        
        meta = {}
        if sender:
            meta['sender'] = sender
        if sha256:
            meta['sha256'] = sha256
        if filename:
            meta['filename'] = filename
        if description:
            meta['description'] = description

        # Screenshot Handler
        screenshot_file = request.files.get('screenshot')
        screenshot_path = None
        if screenshot_file and screenshot_file.filename:
            # Save upload safely inside instance or static upload folder
            filename_secured = secure_filename(screenshot_file.filename)
            uploads_dir = os.path.join(current_app.root_path, 'static', 'uploads')
            os.makedirs(uploads_dir, exist_ok=True)
            screenshot_path = f"/static/uploads/{filename_secured}"
            screenshot_file.save(os.path.join(uploads_dir, filename_secured))

        sub = AIScamAnalyzer.process_submission(
            user_id=current_user.id,
            submission_type=submission_type,
            content=content,
            meta=meta,
            screenshot_path=screenshot_path
        )
        
        flash("Threat submitted successfully to AI decision engine.", "success")
        return redirect(url_for('mobile.history'))

    return render_template('mobile/submit.html')

@mobile_bp.route('/scan/link', methods=['GET', 'POST'])
@login_required
def scan_link():
    result = None
    if request.method == 'POST':
        url = request.form.get('url', '')
        result = AIScamAnalyzer.analyze_content('url', url)
        # Process and save submission to DB
        AIScamAnalyzer.process_submission(
            user_id=current_user.id,
            submission_type='url',
            content=url
        )
    return render_template('mobile/scan_link.html', result=result)

@mobile_bp.route('/scan/sms', methods=['GET', 'POST'])
@login_required
def scan_sms():
    result = None
    if request.method == 'POST':
        sender = request.form.get('sender', '')
        message = request.form.get('message', '')
        result = AIScamAnalyzer.analyze_content('sms', message, {'sender': sender})
        # Process and save submission to DB
        AIScamAnalyzer.process_submission(
            user_id=current_user.id,
            submission_type='sms',
            content=message,
            meta={'sender': sender}
        )
    return render_template('mobile/scan_sms.html', result=result)

@mobile_bp.route('/scan/whatsapp', methods=['GET', 'POST'])
@login_required
def scan_whatsapp():
    result = None
    if request.method == 'POST':
        chat_content = request.form.get('chat_content', '')
        result = AIScamAnalyzer.analyze_content('whatsapp', chat_content)
        # Process and save submission to DB
        AIScamAnalyzer.process_submission(
            user_id=current_user.id,
            submission_type='whatsapp',
            content=chat_content
        )
    return render_template('mobile/scan_whatsapp.html', result=result)

@mobile_bp.route('/scan/email', methods=['GET', 'POST'])
@login_required
def scan_email():
    result = None
    if request.method == 'POST':
        sender = request.form.get('sender', '')
        subject = request.form.get('subject', '')
        body = request.form.get('body', '')
        headers = request.form.get('headers', '')
        
        result = AIScamAnalyzer.analyze_content('email', body, {'sender': sender, 'subject': subject, 'headers': headers})
        # Process and save submission to DB
        AIScamAnalyzer.process_submission(
            user_id=current_user.id,
            submission_type='email',
            content=body,
            meta={'sender': sender, 'subject': subject, 'headers': headers}
        )
    return render_template('mobile/scan_email.html', result=result)

@mobile_bp.route('/scan/qr', methods=['GET', 'POST'])
@login_required
def scan_qr():
    result = None
    if request.method == 'POST':
        decoded_text = request.form.get('decoded_text', '')
        result = AIScamAnalyzer.analyze_content('qr', decoded_text)
        # Process and save submission to DB
        AIScamAnalyzer.process_submission(
            user_id=current_user.id,
            submission_type='qr',
            content=decoded_text
        )
    return render_template('mobile/scan_qr.html', result=result)

@mobile_bp.route('/scan/apk', methods=['GET', 'POST'])
@login_required
def scan_apk():
    result = None
    if request.method == 'POST':
        sha256 = request.form.get('sha256', '')
        filename = request.form.get('filename', '')
        
        result = AIScamAnalyzer.analyze_content('apk', filename, {'sha256': sha256})
        # Process and save submission to DB
        AIScamAnalyzer.process_submission(
            user_id=current_user.id,
            submission_type='apk',
            content=filename,
            meta={'sha256': sha256, 'filename': filename}
        )
    return render_template('mobile/scan_apk.html', result=result)

@mobile_bp.route('/score')
@login_required
def security_score():
    score = calculate_user_security_score(current_user.id)
    submissions = MobileSubmission.query.filter_by(user_id=current_user.id).order_by(MobileSubmission.created_at.desc()).all()
    
    # Calculate totals
    total_scans = len(submissions)
    warn_count = sum(1 for s in submissions if s.verdict == 'WARN')
    block_count = sum(1 for s in submissions if s.verdict == 'BLOCK')
    escalate_count = sum(1 for s in submissions if s.verdict == 'ESCALATE')
    
    return render_template(
        'mobile/score.html',
        score=score,
        total_scans=total_scans,
        warn_count=warn_count,
        block_count=block_count,
        escalate_count=escalate_count,
        submissions=submissions
    )

@mobile_bp.route('/history')
@login_required
def history():
    submissions = MobileSubmission.query.filter_by(user_id=current_user.id).order_by(MobileSubmission.created_at.desc()).all()
    return render_template('mobile/history.html', submissions=submissions)

@mobile_bp.route('/assistant', methods=['GET', 'POST'])
@login_required
def assistant():
    bot_response = None
    user_query = None
    if request.method == 'POST':
        user_query = request.form.get('query', '').strip()

        # Smart rule-based AI security response mapping (RC-2: structured output)
        q = user_query.lower()

        if 'kyc' in q or 'bank' in q or 'account' in q:
            bot_response = {
                'risk': 'High',
                'confidence': '91%',
                'threat_type': 'Banking / KYC Phishing',
                'reason': (
                    'This message contains urgent language around KYC verification or account activation — '
                    'a classic social-engineering technique used by financial fraudsters to steal credentials.'
                ),
                'recommendation': (
                    'Do NOT click any link or call any number in the message. '
                    'Contact your bank directly using the official toll-free number printed on the back of your card.'
                ),
            }
        elif 'won' in q or 'lottery' in q or 'prize' in q or 'congratulation' in q:
            bot_response = {
                'risk': 'Critical',
                'confidence': '97%',
                'threat_type': 'Lottery / Prize Scam',
                'reason': (
                    'Legitimate lotteries never contact winners via unsolicited SMS or WhatsApp, '
                    'and they never require upfront "processing fees" to release winnings.'
                ),
                'recommendation': (
                    'Ignore and block the sender immediately. '
                    'Report the message to your national cybercrime helpline.'
                ),
            }
        elif 'part-time' in q or 'earn money' in q or 'work from home' in q or 'task' in q:
            bot_response = {
                'risk': 'High',
                'confidence': '88%',
                'threat_type': 'Work-from-Home / Task Scam',
                'reason': (
                    'Scammers recruit victims into doing simple tasks (likes, ratings), '
                    'then demand a security deposit before releasing fraudulent "earnings".'
                ),
                'recommendation': (
                    'Do not make any payment. '
                    'Block the contact and report it to your consumer protection authority.'
                ),
            }
        elif 'upi' in q or 'pin' in q or 'otp' in q or 'collect' in q:
            bot_response = {
                'risk': 'Critical',
                'confidence': '95%',
                'threat_type': 'UPI Payment / OTP Fraud',
                'reason': (
                    'You only enter your secret UPI PIN to SEND money — never to receive a refund, '
                    'cashback, or bonus. Sharing OTPs gives attackers instant access to your account.'
                ),
                'recommendation': (
                    'Reject any UPI collect request you did not initiate. '
                    'Never share OTP or PIN with anyone, including bank employees.'
                ),
            }
        elif 'dhl' in q or 'fedex' in q or 'courier' in q or 'parcel' in q or 'package' in q or 'delivery' in q:
            bot_response = {
                'risk': 'Medium',
                'confidence': '82%',
                'threat_type': 'Fake Courier / Parcel Scam',
                'reason': (
                    'Fraudsters impersonate postal companies demanding small "customs tax" payments '
                    'to release a non-existent parcel, capturing card or UPI details.'
                ),
                'recommendation': (
                    'Use the official courier website to verify any tracking code independently. '
                    'Do not pay through links received via SMS or WhatsApp.'
                ),
            }
        elif 'loan' in q or 'credit' in q or 'emi' in q or 'interest' in q:
            bot_response = {
                'risk': 'High',
                'confidence': '85%',
                'threat_type': 'Loan / Credit Fraud',
                'reason': (
                    'Instant loan offers with no documentation requirements are red flags for '
                    'advance-fee fraud or predatory data-harvesting apps.'
                ),
                'recommendation': (
                    'Apply for loans only through RBI-registered NBFCs or your bank\'s official app. '
                    'Never pay a "processing fee" upfront.'
                ),
            }
        else:
            bot_response = {
                'risk': 'Low',
                'confidence': '73%',
                'threat_type': 'No Active Threat Detected',
                'reason': (
                    'Heuristic analysis did not detect known scam patterns in the submitted text. '
                    'However, novel scam variants emerge daily.'
                ),
                'recommendation': (
                    'Remain cautious: never click unknown links, share OTPs, '
                    'or transfer money to unverified contacts.'
                ),
            }

    return render_template('mobile/assistant.html', user_query=user_query, bot_response=bot_response)

