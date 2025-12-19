import os
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# Configuration
OUTPUT_DIR = "test_emails"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def create_email(filename, sender, recipient, subject, body_text, ip_origin=None, attachment_data=None):
    """
    Helper to build a valid .eml file with headers and optional attachments.
    """
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject
    msg['Date'] = time.strftime("%a, %d %b %Y %H:%M:%S +0000")
    
    # Simulate routing headers
    if ip_origin:
        msg['X-Originating-IP'] = ip_origin
        msg['Received'] = f"from mail.server.com ([{ip_origin}]) by internal.mx with ESMTP"

    # Attach the body text
    msg.attach(MIMEText(body_text, 'plain'))

    # Add attachment if provided
    if attachment_data:
        fname, fcontent = attachment_data
        part = MIMEApplication(fcontent, Name=fname)
        part['Content-Disposition'] = f'attachment; filename="{fname}"'
        msg.attach(part)

    # Save to disk
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(msg.as_bytes())
    print(f"✅ Generated: {filepath}")

# --- 1. The "Clean" Email ---
create_email(
    filename="clean_meeting.eml",
    sender="boss@company.com",
    recipient="you@company.com",
    subject="Meeting Agenda for Q1",
    body_text="Hi team,\n\nPlease review the attached agenda for tomorrow's meeting.\n\nThanks,\nBoss",
    ip_origin="10.0.0.5" # Internal IP (Safe)
)

# --- 2. The "Phishing Link" Email ---
create_email(
    filename="phishing_link.eml",
    sender="security-update@paypal-security.top", # Suspicious TLD
    recipient="victim@company.com",
    subject="URGENT: Your account has been suspended",
    body_text="Dear Customer,\n\nWe detected unusual activity.\nClick here to verify: http://secure-bank-verify.xyz/login\n\nIf you do not act, your account will be locked.\n\nSupport Team",
    ip_origin="192.168.6.66" # Matches your mock intel DB
)

# --- 3. The "Malicious Attachment" Email ---
# We simulate a "bad" attachment content
fake_malware_content = b"This is a dummy file but imagine it has VBA macros: AutoOpen()"

create_email(
    filename="malware_invoice.eml",
    sender="billing@unknown-vendor.com",
    recipient="finance@company.com",
    subject="Invoice INV-2024-001",
    body_text="Please find the attached invoice.",
    ip_origin="45.33.22.11",
    attachment_data=("invoice_scan.docm", fake_malware_content)
)

# --- 4. The "CEO Fraud" Email (Business Email Compromise) ---
create_email(
    filename="ceo_fraud.eml",
    sender="ceo-private@gmail.com",
    recipient="cfo@company.com",
    subject="Urgent Wire Transfer Request",
    body_text="I am in a meeting and cannot talk. I need you to process a wire transfer immediately to this vendor.\n\nSent from my iPad",
    ip_origin="185.220.101.1" # Tor exit node IP (often malicious)
)

print(f"\n🎉 Done! 4 test emails created in the '{OUTPUT_DIR}' folder.")
print("👉 Upload these files via your React Dashboard or use cURL to test the API.")