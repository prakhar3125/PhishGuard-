#!/usr/bin/env python3
"""
Comprehensive Test Suite for PhishGuard RoBERTa Classifier
Tests various phishing techniques and legitimate email patterns
"""

from app.core.ml_classifier import PhishingClassifier


def main():
    print("🚀 Initializing PhishGuard RoBERTa Classifier...")
    print("=" * 80)
    classifier = PhishingClassifier(use_transformer=True)
    
    print("\n" + "=" * 80)
    print("COMPREHENSIVE PHISHING DETECTION TEST SUITE")
    print("=" * 80)
    
    # Comprehensive test cases
    tests = [
        # ===== HIGH-RISK PHISHING ATTEMPTS =====
        {
            'name': 'PayPal Account Suspension Phishing',
            'expected': 'PHISHING',
            'expected_probability': '85-95%',
            'reasons': ['Urgency tactics', 'Brand impersonation', 'Credential request', 'Typosquatting domain'],
            'email': {
                'subject': 'URGENT: Your PayPal Account Has Been Limited - Immediate Action Required',
                'body': '''Dear Valued Customer,
                
We have detected unusual activity on your PayPal account and have temporarily limited access to protect your security.

URGENT ACTION REQUIRED:
Your account will be permanently suspended within 24 hours if you do not verify your identity immediately.

What you need to do:
1. Click here to verify your account: http://paypal-secure-verify.com/account/confirm
2. Enter your login credentials
3. Confirm your payment method and billing information
4. Update your social security number for verification

Failure to complete these steps will result in:
- Permanent account closure
- Loss of funds
- Legal action for policy violations

This is your FINAL WARNING. Act now to avoid suspension.

Security Department
PayPal Inc.''',
                'sender': 'security-alert@paypa1-services.com'
            }
        },
        
        {
            'name': 'IRS Tax Refund Scam',
            'expected': 'PHISHING',
            'expected_probability': '90-98%',
            'reasons': ['Government impersonation', 'Financial incentive', 'Credential harvesting', 'Urgency'],
            'email': {
                'subject': 'IRS Notification: Tax Refund of $2,847.00 Pending - Claim Before December 31',
                'body': '''Internal Revenue Service
Department of Treasury
United States of America

OFFICIAL NOTICE - REF#IRS-2025-849271

Dear Taxpayer,

After reviewing your 2024 tax return, we have determined that you are eligible for an additional refund of $2,847.00.

IMPORTANT: This refund will expire on December 31, 2025 if not claimed immediately.

To claim your refund:
1. Click this secure link: http://irs-refund-claim.com/verify
2. Enter your Social Security Number
3. Provide your bank account details for direct deposit
4. Verify your date of birth and mother's maiden name

Processing time: 24-48 hours after verification

Do not reply to this email. This is an automated notification from the IRS processing center.

This is an OFFICIAL IRS communication. Failure to claim your refund by the deadline will result in forfeiture.

Internal Revenue Service
www.irs.gov''',
                'sender': 'no-reply@irs-treasury-services.com'
            }
        },
        
        {
            'name': 'Microsoft 365 Password Expiration',
            'expected': 'PHISHING',
            'expected_probability': '80-90%',
            'reasons': ['Tech company impersonation', 'Password request', 'Urgency', 'Credential theft'],
            'email': {
                'subject': 'Action Required: Your Microsoft 365 Password Expires Today',
                'body': '''Microsoft Security Team

Your Microsoft 365 password will expire in 2 hours.

To prevent losing access to:
- Outlook email
- OneDrive files  
- Teams meetings
- All Microsoft services

You must update your password immediately by clicking below:

UPDATE PASSWORD NOW: http://microsoft-password-renewal.com/office365

After clicking the link:
1. Enter your current email and password
2. Create a new password
3. Re-enter your current password to confirm

If you don't update within 2 hours, your account will be locked and require IT administrator intervention to unlock.

Microsoft Account Team
One Microsoft Way, Redmond, WA 98052''',
                'sender': 'account-security@microsoft-services.com'
            }
        },
        
        {
            'name': 'Amazon Package Delivery Scam',
            'expected': 'PHISHING',
            'expected_probability': '75-85%',
            'reasons': ['Brand impersonation', 'Urgency', 'Shipping scam', 'URL shortener'],
            'email': {
                'subject': 'Amazon Delivery Failed - Package #AMZ849271KL Held at Warehouse',
                'body': '''Hello,

We attempted to deliver your Amazon package but encountered an issue.

Order Number: AMZ849271KL
Delivery Address: [YOUR ADDRESS]
Items: 3 items - $287.49

PROBLEM: Incorrect shipping address format in our system

Your package is currently held at our local distribution center and will be returned to sender in 48 hours if not claimed.

TO RECEIVE YOUR PACKAGE:
Click here to confirm your delivery address: http://bit.ly/amzn-delivery-confirm

You will need to:
- Verify your Amazon account login
- Confirm shipping address  
- Update payment method (delivery fee: $2.95)

Track your package: http://amazon-tracking-services.net/track

Thank you for shopping with Amazon.

Amazon Logistics Team
Customer Service''',
                'sender': 'delivery-notification@amazon-logistics.net'
            }
        },
        
        {
            'name': 'Bank of America Security Alert',
            'expected': 'PHISHING',
            'expected_probability': '85-95%',
            'reasons': ['Bank impersonation', 'Security threat', 'Credential request', 'Multiple urgency indicators'],
            'email': {
                'subject': '⚠️ SECURITY ALERT: Unusual Activity Detected on Your Account',
                'body': '''BANK OF AMERICA - FRAUD PREVENTION ALERT

Account: ****4829
Alert Time: December 20, 2025 - 12:47 AM EST

We have detected the following suspicious transactions:
- $847.29 - Walmart Online - DECLINED
- $1,249.00 - Best Buy - DECLINED  
- $2,100.00 - International Wire Transfer - PENDING REVIEW

These transactions were flagged as potentially fraudulent. Your account has been temporarily locked to prevent unauthorized charges.

IMMEDIATE ACTION REQUIRED:

To unlock your account and review these transactions:
1. Click here: http://bankofamerica-secure.com/verify-account
2. Enter your Online Banking ID and Passcode
3. Answer security questions
4. Verify recent transactions
5. Update your debit card PIN

⚠️ Your account will remain locked until you complete verification within 12 hours.

For your security, do not share this email or your login credentials with anyone.

Bank of America Fraud Prevention
Security Code: BOA-SEC-29471

© 2025 Bank of America Corporation''',
                'sender': 'fraud-alert@bankofamerica-security.com'
            }
        },
        
        {
            'name': 'Netflix Subscription Payment Failed',
            'expected': 'PHISHING',
            'expected_probability': '70-80%',
            'reasons': ['Subscription scam', 'Payment request', 'Account suspension threat'],
            'email': {
                'subject': 'Netflix - Payment Declined, Update Required',
                'body': '''Hi there,

We were unable to process your monthly Netflix payment.

Your subscription: Premium Plan ($19.99/month)
Payment method: Visa ending in 4829
Status: PAYMENT FAILED

Your Netflix account will be suspended in 3 days if payment is not updated.

To avoid interruption of service:
→ Update payment information: http://netflix-billing-update.com

After updating, you'll continue enjoying:
✓ Unlimited movies and TV shows
✓ Watch on 4 devices simultaneously  
✓ Ultra HD available
✓ Download on mobile

Questions? Visit our Help Center or reply to this email.

The Netflix Team''',
                'sender': 'billing@netflix-payments.com'
            }
        },
        
        {
            'name': 'Cryptocurrency Investment Scam',
            'expected': 'PHISHING',
            'expected_probability': '95-99%',
            'reasons': ['Investment scam', 'Guaranteed returns', 'Urgency', 'Suspicious domain'],
            'email': {
                'subject': '🚀 URGENT: Bitcoin Price Alert - Double Your Investment in 24 Hours',
                'body': '''EXCLUSIVE INVESTMENT OPPORTUNITY - LIMITED TIME

Bitcoin is about to EXPLODE! 

Our AI-powered trading algorithm has identified a massive price surge happening in the next 24 hours. This is your chance to turn $500 into $1,000+ GUARANTEED.

✅ Minimum Investment: $250
✅ Expected Return: 100-300% in 24 hours
✅ Risk Level: ZERO - Money-back guarantee
✅ Already helped 10,000+ investors

URGENT: Only 47 spots remaining!

HOW IT WORKS:
1. Click here to create account: http://crypto-profits-guaranteed.com
2. Deposit Bitcoin or Ethereum
3. Our AI does the trading
4. Withdraw profits after 24 hours

"I made $15,000 in one week!" - John D., New York
"This changed my life. I quit my job!" - Sarah M., California

⏰ OFFER EXPIRES IN 6 HOURS ⏰

Start earning now: http://bit.ly/crypto-ai-profits

This is NOT financial advice. Past performance doesn't guarantee future results. Act now before it's too late!

CryptoWealth AI Team''',
                'sender': 'opportunities@crypto-wealth-ai.biz'
            }
        },
        
        # ===== LEGITIMATE EMAILS =====
        {
            'name': 'Legitimate Work Meeting Reminder',
            'expected': 'SAFE/LEGITIMATE',
            'expected_probability': '5-15%',
            'reasons': ['No urgency tactics', 'No credential requests', 'Professional tone', 'Company domain'],
            'email': {
                'subject': 'Reminder: Q1 Planning Meeting - Monday 10 AM',
                'body': '''Hi Team,

Just a friendly reminder about our Q1 planning meeting scheduled for Monday, December 23rd at 10:00 AM in Conference Room B.

Agenda:
- Review Q4 performance metrics
- Set Q1 objectives and key results
- Discuss resource allocation
- Team capacity planning

Please come prepared with your department updates. If you haven't already, please submit your Q4 reports by end of day Friday.

The meeting should last approximately 90 minutes. Coffee and light refreshments will be provided.

Let me know if you have any questions or can't attend.

Best regards,
Jennifer Martinez
Director of Operations
Acme Corporation
jennifer.martinez@acmecorp.com
Office: (555) 123-4567''',
                'sender': 'jennifer.martinez@acmecorp.com'
            }
        },
        
        {
            'name': 'Legitimate Newsletter Subscription',
            'expected': 'SAFE/LEGITIMATE',
            'expected_probability': '10-20%',
            'reasons': ['Expected content', 'Unsubscribe option', 'Professional formatting', 'Known sender'],
            'email': {
                'subject': 'TechCrunch Weekly: Top Stories in AI and Startups',
                'body': '''Good morning,

Here are this week's top technology stories:

🤖 AI DEVELOPMENTS
• OpenAI announces GPT-5 with improved reasoning capabilities
• Google DeepMind solves complex protein folding challenges
• Microsoft integrates AI copilot into Windows 12

💼 STARTUP FUNDING
• Fintech startup Stripe raises $500M Series F
• EV charging company ChargePoint expands to Europe
• Healthcare AI platform secures $100M from Sequoia

📱 PRODUCT LAUNCHES
• Apple announces iPhone 16 with enhanced AR features
• Samsung unveils foldable tablet prototype
• Meta releases Quest 4 VR headset

🔒 CYBERSECURITY
• Major data breach affects 50 million users
• New ransomware variant targets healthcare providers
• Best practices for securing remote work environments

Read full articles: www.techcrunch.com/weekly

You're receiving this because you subscribed to TechCrunch Weekly.
Unsubscribe | Update preferences | View in browser

TechCrunch © 2025 | 490 2nd Street, San Francisco, CA 94107''',
                'sender': 'newsletter@techcrunch.com'
            }
        },
        
        {
            'name': 'Legitimate Order Confirmation',
            'expected': 'SAFE/LEGITIMATE',
            'expected_probability': '5-15%',
            'reasons': ['Order details', 'No urgency', 'Proper formatting', 'Expected communication'],
            'email': {
                'subject': 'Your Amazon Order #114-8572194-2847291 Has Shipped',
                'body': '''Hello,

Good news! Your package is on the way.

ORDER DETAILS:
Order #114-8572194-2847291
Placed on December 18, 2025

SHIPPING INFORMATION:
Logitech MX Master 3S Wireless Mouse - Graphite
Quantity: 1
Price: $99.99

Shipped via: UPS Ground
Tracking #: 1Z999AA10123456784
Estimated delivery: December 22, 2025

Track your package: 
https://www.amazon.com/progress-tracker/package/114-8572194-2847291

SHIPPING ADDRESS:
John Smith
123 Main Street
Apartment 4B
New York, NY 10001

Need to return an item? Visit our Returns Center:
https://www.amazon.com/returns

Questions about your order? We're here to help:
https://www.amazon.com/contact-us

Thanks for shopping with us!

Amazon Customer Service
www.amazon.com''',
                'sender': 'ship-confirm@amazon.com'
            }
        },
        
        {
            'name': 'Legitimate Bank Statement Notification',
            'expected': 'SAFE/LEGITIMATE',
            'expected_probability': '10-20%',
            'reasons': ['Expected notification', 'No credential request', 'Professional', 'Secure portal link'],
            'email': {
                'subject': 'Your November 2025 Statement is Ready',
                'body': '''Dear John Smith,

Your monthly account statement for November 2025 is now available.

Account: Checking Account ****4829
Statement Period: November 1-30, 2025
Current Balance: $4,287.52

To view your statement:
1. Log in to Online Banking at www.chase.com
2. Navigate to "Statements & Documents"
3. Select November 2025 statement

ACCOUNT SUMMARY:
Beginning Balance: $3,842.18
Deposits: $2,450.00
Withdrawals: $2,004.66
Ending Balance: $4,287.52

If you have paperless statements enabled, this is your only notification. Statements are retained online for 7 years.

For questions about your account, please call us at 1-800-935-9935 or visit your local branch.

Thank you for banking with Chase.

This is an automated message. Please do not reply to this email.

Chase Bank
Member FDIC
Equal Housing Lender

Privacy Policy | Security Center | Contact Us

© 2025 JPMorgan Chase & Co.''',
                'sender': 'statements@alertsp.chase.com'
            }
        },
        
        {
            'name': 'Legitimate Software Update Notification',
            'expected': 'SAFE/LEGITIMATE',
            'expected_probability': '15-25%',
            'reasons': ['Expected update', 'No urgency pressure', 'Official domain', 'Professional tone'],
            'email': {
                'subject': 'Slack: New Features and Improvements Available',
                'body': '''Hi there,

We've released a new version of Slack with exciting features and improvements!

WHAT'S NEW IN VERSION 4.35:
✨ Huddles now support screen sharing
✨ Improved search with AI-powered suggestions
✨ Custom emoji reactions in threads
✨ Enhanced mobile app performance
✨ Dark mode improvements

SECURITY UPDATES:
🔒 Enhanced encryption for messages
🔒 Two-factor authentication improvements
🔒 Better phishing protection

The update will install automatically the next time you restart Slack, or you can update manually:
• Desktop: Help menu → Check for Updates
• Mobile: Update from App Store or Google Play

Release notes: https://slack.com/release-notes/desktop/4.35

Need help? Check out our Help Center or contact support:
https://slack.com/help

Happy Slacking!
The Slack Team

You're receiving this email because you're a Slack workspace member.
Manage email preferences: https://slack.com/account/notifications

Slack Technologies, LLC
500 Howard Street, San Francisco, CA 94105''',
                'sender': 'feedback@slack.com'
            }
        },
        
        {
            'name': 'Legitimate Event Invitation',
            'expected': 'SAFE/LEGITIMATE',
            'expected_probability': '5-10%',
            'reasons': ['Clear event details', 'RSVP option', 'No pressure', 'Professional format'],
            'email': {
                'subject': 'You\'re Invited: Annual Tech Summit 2025 - March 15-17',
                'body': '''Dear Technology Professional,

We're excited to invite you to the Annual Tech Summit 2025!

EVENT DETAILS:
📅 Date: March 15-17, 2025
📍 Location: Moscone Center, San Francisco, CA
🎫 Registration: Early bird pricing until January 31

FEATURED SPEAKERS:
• Sundar Pichai (Google CEO) - Keynote: Future of AI
• Satya Nadella (Microsoft CEO) - Cloud Computing Revolution
• Jensen Huang (NVIDIA CEO) - The Age of Accelerated Computing
• Dr. Fei-Fei Li (Stanford) - AI Ethics and Society

CONFERENCE TRACKS:
🤖 Artificial Intelligence & Machine Learning
☁️ Cloud Infrastructure & DevOps
🔒 Cybersecurity & Privacy
📱 Mobile & Web Development
💼 Tech Leadership & Management

NETWORKING OPPORTUNITIES:
- 50+ exhibitor booths
- Evening reception with speakers
- Roundtable discussions
- Career fair

PRICING:
Early Bird (Until Jan 31): $599
Regular (Feb 1-Mar 1): $799
Late (After Mar 1): $999

Register now: https://www.techsummit2025.com/register
View full schedule: https://www.techsummit2025.com/agenda

Questions? Contact us at info@techsummit2025.com or call (555) 987-6543

We hope to see you there!

Best regards,
Sarah Johnson
Event Director
Tech Summit Conference
www.techsummit2025.com''',
                'sender': 'sarah.johnson@techsummit2025.com'
            }
        },
        
        # ===== BORDERLINE/SUSPICIOUS CASES =====
        {
            'name': 'Borderline: Aggressive Marketing Email',
            'expected': 'SUSPICIOUS (40-60%)',
            'expected_probability': '40-60%',
            'reasons': ['Aggressive tactics but legitimate company', 'Urgency but not credential theft', 'Real unsubscribe'],
            'email': {
                'subject': '⚡ FLASH SALE: 70% OFF Everything - 6 Hours Only! ⚡',
                'body': '''🔥 BIGGEST SALE OF THE YEAR 🔥

This is NOT a drill!

70% OFF EVERYTHING on our website - but ONLY for the next 6 hours!

⏰ HURRY - Sale ends at MIDNIGHT! ⏰

Shop now or regret it forever:
→ Men's Clothing: 70% off
→ Women's Apparel: 70% off  
→ Shoes & Accessories: 70% off
→ Electronics: 70% off

🚨 PLUS: Free shipping on orders over $50! 🚨

Don't miss out! Thousands of customers are shopping right now. Items selling out FAST!

SHOP NOW: www.fashionoutlet.com/flash-sale

This sale is TOO GOOD to last. Once it's gone, it's GONE FOREVER.

Limited quantities. No rain checks. Final sale - all sales final.

Fashion Outlet
Customer Service: support@fashionoutlet.com

Unsubscribe | Update preferences
123 Fashion Ave, New York, NY 10001''',
                'sender': 'sales@fashionoutlet.com'
            }
        },
        
        {
            'name': 'Borderline: LinkedIn Connection Request',
            'expected': 'SUSPICIOUS (30-50%)',
            'expected_probability': '30-50%',
            'reasons': ['Could be legitimate networking or spam', 'Vague connection reason', 'Generic message'],
            'email': {
                'subject': 'Michael Chen wants to connect on LinkedIn',
                'body': '''Hi there,

I'd like to add you to my professional network on LinkedIn.

Michael Chen
Senior Recruiter at TechStaff Solutions
San Francisco Bay Area

View Michael's profile: https://www.linkedin.com/in/michael-chen-recruiter

I came across your profile and was impressed by your background in software engineering. I have some exciting opportunities that might interest you.

Would you be open to a quick 15-minute call this week?

Looking forward to connecting!

Michael

---
You are receiving Invitation emails.
Unsubscribe: https://www.linkedin.com/e/v2/unsub
© 2025 LinkedIn Corporation''',
                'sender': 'invitations@linkedin.com'
            }
        }
    ]
    
    # Run tests
    for i, test in enumerate(tests, 1):
        print(f"\n{'='*80}")
        print(f"TEST #{i}: {test['name']}")
        print(f"{'='*80}")
        print(f"📋 Expected Result: {test['expected']}")
        print(f"📊 Expected Probability: {test['expected_probability']}")
        print(f"🔍 Key Indicators: {', '.join(test['reasons'])}")
        print(f"\n📧 EMAIL DETAILS:")
        print(f"   From: {test['email']['sender']}")
        print(f"   Subject: {test['email']['subject']}")
        print(f"\n   Body Preview:")
        body_preview = test['email']['body'][:300] + "..." if len(test['email']['body']) > 300 else test['email']['body']
        for line in body_preview.split('\n'):
            if line.strip():
                print(f"   {line}")
        
        print(f"\n🤖 RUNNING ANALYSIS...")
        result = classifier.predict(test['email'])
        
        # Determine verdict
        if result['is_phishing']:
            verdict = "🚨 PHISHING DETECTED"
            color = "RED"
        else:
            verdict = "✅ APPEARS SAFE"
            color = "GREEN"
        
        print(f"\n{'─'*80}")
        print(f"🎯 RESULT: {verdict}")
        print(f"{'─'*80}")
        print(f"   Phishing Probability: {result['phishing_probability']:.1%}")
        print(f"   Legitimate Probability: {result.get('legitimate_probability', 1-result['phishing_probability']):.1%}")
        print(f"   Confidence Score: {result.get('confidence', 0):.1%}")
        print(f"   Detection Method: {result['method']}")
        
        # Show match with expected result
        expected_phishing = test['expected'] == 'PHISHING'
        actual_phishing = result['is_phishing']
        
        if expected_phishing == actual_phishing:
            print(f"\n   ✅ CORRECT - Matches expected result!")
        else:
            print(f"\n   ⚠️  MISMATCH - Expected: {test['expected']}, Got: {'PHISHING' if actual_phishing else 'SAFE'}")
        
        # Show indicators if available
        if 'indicators' in result:
            print(f"\n   📍 Detected Indicators:")
            for indicator in result['indicators'][:5]:  # Show top 5
                print(f"      • {indicator}")
    
    # Summary
    print(f"\n{'='*80}")
    print("TEST SUITE COMPLETED")
    print(f"{'='*80}")
    print(f"Total Tests Run: {len(tests)}")
    print(f"\nℹ️  Note: Results may vary based on model version and training data.")
    print("For production use, consider implementing ensemble methods and")
    print("human-in-the-loop verification for borderline cases (40-60% probability).")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
