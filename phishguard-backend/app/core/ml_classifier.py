import joblib
import numpy as np
import re
import os
from typing import Dict, Optional, List
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# Hugging Face imports
try:
    from transformers import (
        AutoTokenizer, 
        AutoModelForSequenceClassification,
        pipeline
    )
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("⚠️  transformers not installed. Run: pip install transformers torch")

class PhishingClassifier:
    def __init__(self, 
                 model_path: str = None, 
                 use_transformer: bool = True):
        """
        Initialize Phishing Classifier with RoBERTa model
        
        Args:
            model_path: Path to local transformer model (e.g. "my_local_model")
            use_transformer: Whether to use Hugging Face RoBERTa model
        """
        # Paths for the Traditional (Fallback) Model
        self.traditional_model_path = './models/phishing_model.pkl'
        self.vectorizer_path = './models/vectorizer.pkl'
        
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        
        # Transformer Settings
        self.use_transformer = use_transformer and TRANSFORMERS_AVAILABLE
        
        # ✅ FIX: Smart Model Path Selection
        # 1. If model_path is provided and exists as a folder, use it (Local Mode)
        # 2. If not, fallback to the Hugging Face Cloud ID
        if model_path and os.path.exists(model_path):
            print(f"📂 Found local model at: {model_path}")
            self.transformer_model_name = model_path
        else:
            print("🌐 Local model not found. Using Hugging Face cloud model.")
            self.transformer_model_name = 'ealvaradob/bert-finetuned-phishing'

        self.tokenizer = None
        self.transformer_model = None
        self.transformer_pipeline = None
        self.transformer_loaded = False
        
        # Device selection (GPU if available)
        self.device = 0 if torch.cuda.is_available() else -1
        device_name = "cuda" if self.device == 0 else "cpu"
        print(f"🖥️  Using device: {device_name}")
        
        # Load models
        if self.use_transformer:
            self._load_transformer()
        else:
            self._load_traditional_model()
    
    def _load_traditional_model(self):
        """Load traditional ML model (fallback)"""
        if os.path.exists(self.traditional_model_path) and os.path.exists(self.vectorizer_path):
            try:
                self.model = joblib.load(self.traditional_model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                self.is_trained = True
                print("✓ Traditional ML Model loaded successfully")
            except Exception as e:
                print(f"✗ Error loading traditional model: {e}")
                self.is_trained = False
        else:
            print("ℹ️  No traditional model found (will use heuristic fallback)")
    
    def _load_transformer(self):
        """Load pre-trained RoBERTa phishing detection model"""
        if not TRANSFORMERS_AVAILABLE:
            print("⚠️  Transformers not available, falling back to traditional ML")
            self.use_transformer = False
            self._load_traditional_model()
            return
        
        try:
            print(f"📦 Loading phishing model from: {self.transformer_model_name}...")
            
            # Load tokenizer and model
            self.tokenizer = AutoTokenizer.from_pretrained(self.transformer_model_name)
            self.transformer_model = AutoModelForSequenceClassification.from_pretrained(
                self.transformer_model_name
            )
            
            # Create pipeline for easy inference
            self.transformer_pipeline = pipeline(
                "text-classification",
                model=self.transformer_model,
                tokenizer=self.tokenizer,
                device=self.device,
                top_k=None  # Return all scores
            )
            
            self.transformer_loaded = True
            print("✓ RoBERTa phishing model loaded successfully")
            
        except Exception as e:
            print(f"✗ Error loading transformer: {e}")
            print("⚠️  Falling back to traditional ML")
            self.use_transformer = False
            self._load_traditional_model()
    
    def train(self, emails: list, labels: list):
        """Train traditional ML model (fallback only)"""
        print("🔧 Training traditional ML model...")
        
        # Initialize vectorizer
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english',
            min_df=2,
            max_df=0.95
        )
        
        # Extract features
        X = self.vectorizer.fit_transform(emails)
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X, labels)
        
        # Save model
        os.makedirs('./models', exist_ok=True)
        joblib.dump(self.model, self.traditional_model_path)
        joblib.dump(self.vectorizer, self.vectorizer_path)
        
        self.is_trained = True
        print("✓ Traditional model trained and saved successfully")
    
    def predict(self, email_content: Dict) -> Dict:
        """
        Predict if email is phishing using best available model
        """
        # Prepare email text
        email_text = self._prepare_email_text(email_content)
        
        # Use RoBERTa transformer if available
        if self.use_transformer and self.transformer_loaded:
            return self._predict_with_transformer(email_text)
        
        # Fallback to traditional ML
        elif self.is_trained:
            return self._predict_with_traditional(email_text)
        
        # Last resort: heuristic
        else:
            return self._heuristic_prediction(email_content)
 
    def _predict_with_transformer(self, email_text: str) -> Dict:
            """Predict using Transformer model with dynamic label handling"""
            try:
                # Truncate if too long (standard limit is 512 tokens)
                max_length = 512
                
                with torch.no_grad():
                    results = self.transformer_pipeline(
                        email_text[:2000], 
                        truncation=True,
                        max_length=max_length
                    )
                
                phishing_score = 0.0
                legitimate_score = 0.0
                
                # We check for various label names so it works with ANY model
                phishing_aliases = ['phishing', 'spam', 'malicious', 'label_1', '1']
                legit_aliases = ['benign', 'ham', 'legitimate', 'safe', 'label_0', '0']
                
                for result in results[0]:
                    label_clean = result['label'].lower()
                    score = result['score']
                    
                    if any(alias in label_clean for alias in phishing_aliases):
                        phishing_score = score
                    elif any(alias in label_clean for alias in legit_aliases):
                        legitimate_score = score
                
                # Fallback if model only returns one label
                if phishing_score == 0.0 and legitimate_score > 0.0:
                    phishing_score = 1.0 - legitimate_score
                elif legitimate_score == 0.0 and phishing_score > 0.0:
                    legitimate_score = 1.0 - phishing_score
                    
                is_phishing = phishing_score > legitimate_score
                confidence = max(phishing_score, legitimate_score)
                
                return {
                    'is_phishing': is_phishing,
                    'phishing_probability': float(phishing_score),
                    'legitimate_probability': float(legitimate_score),
                    'confidence': float(confidence),
                    'method': 'roberta_transformer',
                    'model': 'local_model' if os.path.exists(self.transformer_model_name) else self.transformer_model_name
                }
            
            except Exception as e:
                print(f"⚠️  Transformer prediction error: {e}")
                # Fallback to heuristic
                return self._heuristic_prediction({'body': email_text})    
    
    def _predict_with_traditional(self, email_text: str) -> Dict:
        """Predict using traditional ML model"""
        try:
            # Transform and predict
            X = self.vectorizer.transform([email_text])
            prediction = self.model.predict(X)[0]
            proba = self.model.predict_proba(X)[0]
            
            return {
                'is_phishing': bool(prediction),
                'phishing_probability': float(proba[1]),
                'legitimate_probability': float(proba[0]),
                'confidence': float(max(proba)),
                'method': 'traditional_ml',
                'model': 'RandomForest'
            }
        
        except Exception as e:
            print(f"⚠️  Traditional ML error: {e}")
            return self._heuristic_prediction({'body': email_text})
    
    def _prepare_email_text(self, email_content: Dict) -> str:
        """Prepare email content for prediction"""
        parts = []
        
        if email_content.get('subject'):
            parts.append(f"Subject: {email_content['subject']}")
        
        if email_content.get('sender'):
            parts.append(f"From: {email_content['sender']}")
        
        if email_content.get('body'):
            body = email_content['body']
            body = ' '.join(body.split())
            parts.append(body)
        
        return ' '.join(parts)
    
    def _heuristic_prediction(self, email_content: Dict) -> Dict:
        """Fallback heuristic-based prediction when ML models unavailable"""
        score = 0
        indicators = []
        
        subject = email_content.get('subject', '').lower()
        body = email_content.get('body', '').lower()
        sender = email_content.get('sender', '').lower()
        
        # --- HEURISTIC LISTS ---
        
        phishing_keywords = [
            'urgent', 'immediately', 'act now', 'action required', 'respond now',
            'within 24 hours', 'expires today', 'expire', 'expiration', 'time sensitive',
            'limited time', 'deadline', 'asap', 'right away', 'don\'t delay',
            'last chance', 'final notice', 'final warning', 'immediate action',
            'verify', 'verify your account', 'verify your identity', 'verify now',
            'confirm your account', 'confirm identity', 'confirm your information',
            'suspended', 'suspension', 'locked', 'lock', 'restricted', 'restriction',
            'unusual activity', 'suspicious activity', 'unauthorized access',
            'security alert', 'security warning', 'security breach', 'compromised',
            'fraudulent activity', 'protect your account', 'secure your account',
            'validation required', 'authenticate', 'reactivate', 're-activate',
            'update payment', 'payment failed', 'payment declined', 'billing problem',
            'billing issue', 'credit card', 'debit card', 'bank account',
            'account on hold', 'payment information', 'update billing',
            'invoice', 'refund', 'tax refund', 'irs refund', 'tax return',
            'overdue', 'past due', 'outstanding balance', 'payment pending',
            'transaction failed', 'declined payment', 'charge failed',
            'congratulations', 'you won', 'you\'ve won', 'winner', 'prize',
            'claim your prize', 'claim your reward', 'reward', 'bonus',
            'gift card', 'free gift', 'lottery', 'sweepstakes', 'jackpot',
            'selected', 'chosen', 'lucky winner', 'cash prize',
            'click here', 'click below', 'click link', 'click now',
            'download', 'open attachment', 'view document', 'verify here',
            'login here', 'sign in', 'update here', 'reset password',
            'reset now', 'change password', 'recover account',
            'social security', 'ssn', 'social security number', 'tax id',
            'date of birth', 'mother\'s maiden name', 'full name',
            'account number', 'routing number', 'pin', 'cvv', 'security code',
            'password', 'username', 'credentials', 'personal information',
            'will be closed', 'account closure', 'terminate', 'termination',
            'legal action', 'lawsuit', 'suspended permanently', 'lose access',
            'cancel', 'cancellation', 'deactivate', 'deactivated',
            'lose your account', 'blocked', 'disabled',
            'this is not spam', 'legitimate', 'not a scam', 'official notice',
            'authorized', 'verified sender', 'trusted', 'secure message',
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'bank of america', 'wells fargo', 'chase', 'irs', 'irs.gov',
            'fedex', 'ups', 'dhl', 'usps', 'netflix', 'spotify',
            'important', 'critical', 'alert', 'warning', 'attention',
            'notification', 'notice', 'dear customer', 'dear user',
            'valued customer', 'account holder', 'member',
            'system update', 'software update', 'security update',
            'maintenance', 'server error', 'technical issue',
            'upgrade required', 'new policy', 'terms updated',
            'covid', 'coronavirus', 'vaccine', 'relief fund', 'stimulus',
            'government grant', 'emergency fund',
            'bitcoin', 'crypto', 'cryptocurrency', 'investment opportunity',
            'trading', 'profit', 'earn money', 'make money fast',
            'get rich', 'guaranteed returns', 'double your money',
            'package delivery', 'shipment', 'tracking', 'delivery failed',
            'undelivered', 'courier', 'customs', 'held at warehouse',
            'account suspended', 'account locked', 'account blocked',
            'account verification', 'unusual sign-in', 'new device',
            'location', 'ip address', 'multiple attempts'
        ]

        for keyword in phishing_keywords:
            if keyword in subject:
                score += 15
                indicators.append(f'Suspicious keyword: {keyword}')
        
        urgency_words = [
            'urgent', 'urgently', 'emergency', 'critical', 'immediately', 
            'instant', 'now', 'right now', 'asap', 'a.s.a.p', 'today',
            'tonight', 'at once', 'without delay', 'promptly',
            'action required', 'immediate action', 'action needed',
            'respond immediately', 'respond now', 'reply immediately',
            'act fast', 'act quickly', 'take action', 'must act',
            'require immediate attention', 'needs your attention',
            'expires', 'expiring', 'expire today', 'expires soon',
            'deadline', 'time limit', 'limited time', 'last day',
            'final day', 'ends today', 'ends tonight', 'ends soon',
            'within 24 hours', 'within 48 hours', 'by midnight',
            'before it\'s too late', 'running out', 'time is running out',
            'last chance', 'final notice', 'final warning', 'final reminder',
            'final attempt', 'last opportunity', 'don\'t miss out',
            'don\'t wait', 'don\'t delay', 'can\'t wait', 'won\'t last',
            'suspend', 'suspended', 'will be suspended', 'suspension',
            'close your account', 'account closure', 'will be closed',
            'terminate', 'termination', 'will be terminated',
            'lose access', 'will lose', 'locked out', 'deactivate',
            'will be deactivated', 'cancelled', 'will be cancelled',
            'time-sensitive', 'time sensitive', 'time critical',
            'pending', 'awaiting', 'requires immediate', 'overdue',
            'past due', 'due today', 'due now', 'waiting for you',
            'quick', 'quickly', 'fast', 'swift', 'rapid',
            'hurry', 'rush', 'speed', 'speedy', 'instant response',
            'seconds', 'minutes', 'hours left', 'days left',
            'countdown', 'ticking', 'clock is ticking',
            'this instant', 'this moment', 'right away',
            'alert', 'warning', 'attention required', 'attention needed',
            'important notice', 'urgent notice', 'critical alert',
            'security alert', 'fraud alert', 'immediate notice',
            'will be deleted', 'permanent deletion', 'permanently',
            'irreversible', 'cannot be undone', 'will forfeit',
            'miss out', 'opportunity expires', 'gone forever',
            'must', 'need to', 'have to', 'required to',
            'mandatory', 'compulsory', 'obligated', 'necessary',
            'essential', 'vital', 'crucial',
            'limited offer', 'offer ends', 'while supplies last',
            'slots filling up', 'almost gone', 'selling fast',
            'only a few left', 'spots remaining'
        ]

        urgency_count = sum(1 for word in urgency_words if word in subject or word in body)
        if urgency_count > 0:
            score += urgency_count * 10
            indicators.append('Uses urgency tactics')
        
        credential_words = [
            'password', 'passwords', 'passcode', 'pass code', 'passphrase',
            'username', 'user name', 'user id', 'userid', 'login',
            'log in', 'sign in', 'signin', 'credentials', 'authentication',
            'auth code', 'access code', 'security code', 'pin', 'pin number',
            'verify', 'verify account', 'verify identity', 'verify information',
            'confirm', 'confirm account', 'confirm identity', 'confirm details',
            'validate', 'validation', 'authenticate', 'reconfirm',
            'update account', 'update information', 'update details',
            'account', 'account information', 'account details',
            'ssn', 'social security', 'social security number', 'social security #',
            'tax id', 'tax identification', 'ein', 'itin',
            'date of birth', 'birth date', 'dob', 'd.o.b',
            'driver\'s license', 'driver license', 'drivers license', 'dl number',
            'passport', 'passport number', 'national id', 'citizen id',
            'full name', 'legal name', 'maiden name', 'mother\'s maiden name',
            'credit card', 'credit card number', 'card number', 'cc number',
            'debit card', 'bank card', 'card details', 'card info',
            'cvv', 'cvv2', 'cvc', 'security code', 'verification code',
            'expiration date', 'expiry date', 'exp date', 'valid thru',
            'bank account', 'account number', 'acct number', 'checking account',
            'savings account', 'routing number', 'aba number', 'swift code',
            'iban', 'sort code', 'bank details', 'banking information',
            'payment method', 'payment information', 'billing information',
            'billing address', 'billing details', 'payment details',
            'paypal password', 'paypal account', 'payment account',
            'security question', 'security answer', 'secret question',
            'secret answer', 'recovery question', 'reset password',
            'change password', 'new password', 'old password',
            'current password', 'temporary password', 'one-time password',
            'otp', 'verification code', '2fa', 'two-factor', 'mfa',
            'authenticator', 'backup codes', 'recovery codes',
            'email address', 'phone number', 'mobile number', 'cell number',
            'address', 'home address', 'street address', 'zip code',
            'postal code', 'city', 'state', 'country',
            'salary', 'income', 'annual income', 'employer', 'employer name',
            'employee id', 'work email', 'company name', 'job title',
            'health insurance', 'insurance number', 'policy number',
            'medical records', 'healthcare', 'medicare number',
            'insurance card', 'subscriber id',
            'private key', 'seed phrase', 'recovery phrase', 'wallet address',
            'wallet password', 'crypto password', 'exchange password',
            '12 word phrase', '24 word phrase', 'mnemonic',
            'access token', 'api key', 'session token', 'auth token',
            'access credentials', 'login details', 'account access',
            'unlock account', 'regain access', 'restore access',
            'photo id', 'government id', 'identification', 'id card',
            'identity verification', 'identity proof', 'proof of identity',
            'document upload', 'scan id', 'upload document',
            'apple id', 'google account', 'microsoft account', 'facebook password',
            'gmail password', 'icloud password', 'amazon password',
            'student id', 'enrollment number', 'registration number',
            'license number', 'certification', 'membership number',
            'fingerprint', 'face scan', 'facial recognition', 'voice verification',
            'biometric', 'scan your face', 'verify face',
            'enter your', 'provide your', 'submit your', 'input your',
            'fill in your', 'type your', 'share your', 'send us your',
            'give us your', 'we need your', 'supply your'
        ]

        credential_count = sum(1 for word in credential_words if word in body)
        if credential_count >= 2:
            score += 20
            indicators.append('Requests sensitive information')
        
        # Check sender domain spoofing
        if '@' in sender:
            sender_domain = sender.split('@')[1] if '@' in sender else ''
            brands = [
                'paypal', 'venmo', 'zelle', 'cash app', 'cashapp', 'stripe',
                'square', 'payoneer', 'skrill', 'worldpay', 'wise', 'transferwise',
                'revolut', 'chime', 'robinhood',
                'amazon', 'ebay', 'walmart', 'target', 'alibaba', 'aliexpress',
                'etsy', 'shopify', 'wayfair', 'bestbuy', 'best buy', 'costco',
                'home depot', 'homedepot', 'lowes', "lowe's",
                'microsoft', 'google', 'apple', 'meta', 'facebook', 'instagram',
                'twitter', 'x corp', 'linkedin', 'zoom', 'slack', 'adobe',
                'oracle', 'salesforce', 'dropbox', 'docusign',
                'bank', 'chase', 'bank of america', 'wellsfargo', 'wells fargo',
                'citibank', 'citi', 'us bank', 'pnc', 'capital one', 'capitalone',
                'td bank', 'truist', 'fifth third', 'regions bank', 'bmo',
                'hsbc', 'barclays', 'lloyds', 'natwest', 'santander', 'bbva',
                'deutsche bank', 'bnp paribas', 'credit suisse', 'ubs',
                'ing', 'rabobank', 'scotiabank', 'rbc', 'royal bank',
                'visa', 'mastercard', 'american express', 'amex', 'discover',
                'capital one', 'synchrony',
                'netflix', 'hulu', 'disney', 'disney+', 'hbo', 'hbo max',
                'amazon prime', 'spotify', 'youtube', 'peacock', 'paramount',
                'apple tv', 'crunchyroll',
                'office 365', 'microsoft 365', 'onedrive', 'sharepoint',
                'google drive', 'gmail', 'outlook', 'icloud', 'aws',
                'azure', 'quickbooks', 'turbotax', 'norton', 'mcafee',
                'coinbase', 'binance', 'kraken', 'crypto.com', 'gemini',
                'bitfinex', 'bitstamp', 'blockchain', 'metamask',
                'fedex', 'ups', 'usps', 'dhl', 'royal mail', 'canada post',
                'hermes', 'dpd', 'purolator',
                'irs', 'social security', 'medicare', 'medicaid', 'hmrc',
                'canada revenue', 'cra', 'ato', 'centrelink',
                'verizon', 'at&t', 'att', 't-mobile', 'tmobile', 'sprint',
                'comcast', 'xfinity', 'spectrum', 'cox', 'vodafone',
                'bt', 'rogers', 'bell', 'telus',
                'blue cross', 'aetna', 'cigna', 'united healthcare', 'humana',
                'kaiser', 'anthem', 'wellcare',
                'booking.com', 'expedia', 'airbnb', 'hotels.com', 'trivago',
                'marriott', 'hilton', 'delta', 'american airlines', 'united airlines',
                'southwest', 'uber', 'lyft', 'doordash', 'grubhub',
                'steam', 'playstation', 'xbox', 'nintendo', 'epic games',
                'roblox', 'fortnite', 'twitch', 'discord',
                'coursera', 'udemy', 'linkedin learning', 'zoom', 'teams',
                'webex', 'canvas', 'blackboard',
                'norton', 'mcafee', 'avast', 'avg', 'kaspersky', 'bitdefender',
                'malwarebytes', 'trend micro', 'symantec',
                'tinder', 'bumble', 'match.com', 'eharmony', 'hinge',
                'whatsapp', 'telegram', 'signal', 'snapchat', 'tiktok',
                'indeed', 'monster', 'glassdoor', 'ziprecruiter', 'careerbuilder',
                'godaddy', 'namecheap', 'bluehost', 'hostgator', 'squarespace',
                'wix', 'wordpress'
            ]
            
            for brand in brands:
                if brand in sender_domain:
                    official_domains = [f'{brand}.com', f'{brand}.co.uk']
                    if not any(sender_domain.endswith(official) for official in official_domains):
                        score += 35
                        indicators.append(f'Brand impersonation: {brand}')
        
        # Check for suspicious URLs
        url_pattern = re.compile(r'https?://[^\s]+')
        urls = url_pattern.findall(body)
        if len(urls) > 3:
            score += 10
            indicators.append(f'Multiple URLs ({len(urls)})')
        
        url_shorteners = [
            'bit.ly', 'bitly.com', 'tinyurl.com', 'goo.gl', 't.co',
            'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bl.ink',
            'lnkd.in', 'ift.tt', 'soo.gd', 'cli.gs', 's2r.co',
            'clicky.me', 'budurl.com', 'bc.vc', 'u.to', 'tiny.cc',
            'youtu.be', 'fb.me', 'fb.com', 'amzn.to', 'amzn.com',
            'apple.co', 'g.co', 'sptfy.com', 'lnkd.in', 'trib.al',
            'spr.ly', 'po.st', 'cutt.ly', 'short.io', 'rebrand.ly',
            'clk.sh', 'hyper.host', 'shorturl.at', 'qr.ae', 'qr.net',
            'scan.me', 'go.shr.lc', 'clickmeter.com', 'smarturl.it',
            'genius.com', 'linktr.ee', 'hubs.ly', 'ctt.ac', 'ctt.ec',
            'adf.ly', 'bc.vc', 'zip.net', 'cur.lv', 'alturl.com',
            'vzturl.com', 'migre.me', 'fur.ly', 'rb.gy', 'short.cm',
            'tiny.one', 'cutly.link', 'shorturl.com', 'v.gd', 'tr.im',
            'x.co', 'short.link', 'zee.gl', 'urlz.fr', 'lstu.fr',
            'git.io', 'deck.ly', 'su.pr', 'j.mp', 'kl.am', 'wp.me',
            'dlvr.it', 'su.pr', 'ff.im', 'digg.com/d', 'moourl.com',
            'snipurl.com', 'chilp.it', 'u.nu', 'snipr.com', 'flic.kr',
            'rubyurl.com', 'tweez.me', 'twitthis.com', '2tu.us', 'to.ly',
            'nn.nf', 'go2.me', '*.tk', '*.ml', '*.ga', '*.cf', '*.gq'
        ]

        # Check for URL shorteners
        if any(short in body for short in url_shorteners):
            score += 15
            indicators.append('Uses URL shorteners')
        
        # Normalize score to probability
        probability = min(score / 100, 1.0)
        
        return {
            'is_phishing': probability > 0.5,
            'phishing_probability': probability,
            'legitimate_probability': 1.0 - probability,
            'confidence': 0.6,
            'method': 'heuristic',
            'indicators': indicators
        }
    
    def extract_features(self, email_content: Dict) -> Dict:
        """Extract detailed features for analysis"""
        features = {}
        
        subject = email_content.get('subject', '')
        body = email_content.get('body', '')
        sender = email_content.get('sender', '')
        
        # Length features
        features['subject_length'] = len(subject)
        features['body_length'] = len(body)
        features['has_attachments'] = len(email_content.get('attachments', [])) > 0
        
        # URL features
        url_pattern = re.compile(r'https?://[^\s]+')
        urls = url_pattern.findall(body)
        features['url_count'] = len(urls)
        features['has_shortened_url'] = any(short in body for short in ['bit.ly', 'tinyurl', 'goo.gl'])
        
        # Suspicious patterns
        features['has_urgency'] = any(word in subject.lower() + body.lower() 
                                     for word in ['urgent', 'immediate', 'act now'])
        features['requests_credentials'] = any(word in body.lower() 
                                              for word in ['password', 'verify account', 'confirm identity'])
        
        # Sender analysis
        features['sender_domain'] = sender.split('@')[1] if '@' in sender else ''
        features['has_suspicious_tld'] = any(tld in sender for tld in ['.xyz', '.tk', '.ml', '.ga'])
        
        return features
    
    def get_model_info(self) -> Dict:
        """Get information about loaded models"""
        return {
            'transformer_available': self.use_transformer,
            'transformer_loaded': self.transformer_loaded,
            'transformer_model': self.transformer_model_name if self.use_transformer else None,
            'traditional_trained': self.is_trained,
            'device': 'cuda' if self.device == 0 else 'cpu',
            'model_type': 'Pre-trained RoBERTa for Phishing Detection'
        }
    
    def batch_predict(self, emails: List[Dict]) -> List[Dict]:
        """
        Predict multiple emails efficiently
        
        Args:
            emails: List of email content dictionaries
        
        Returns:
            List of prediction results
        """
        results = []
        
        if self.use_transformer and self.transformer_loaded:
            # Prepare all texts
            texts = [self._prepare_email_text(email) for email in emails]
            
            # Batch prediction
            try:
                predictions = self.transformer_pipeline(
                    texts,
                    truncation=True,
                    max_length=512,
                    batch_size=8
                )
                
                for pred_list in predictions:
                    phishing_score = 0.0
                    for result in pred_list:
                        # Assuming LABEL_1 is phishing based on typical datasets
                        if result['label'] in ['LABEL_1', 'phishing', 'spam']:
                            phishing_score = result['score']
                    
                    results.append({
                        'is_phishing': phishing_score > 0.5,
                        'phishing_probability': float(phishing_score),
                        'method': 'roberta_transformer'
                    })
                
                return results
            
            except Exception as e:
                print(f"Batch prediction error: {e}")
        
        # Fallback to individual predictions
        for email in emails:
            results.append(self.predict(email))
        
        return results


# ===== Testing Utility =====

if __name__ == "__main__":
    print("=" * 60)
    print("PhishGuard RoBERTa Phishing Classifier - Testing")
    print("=" * 60)
    
    # Initialize classifier
    classifier = PhishingClassifier(use_transformer=True)
    
    # Get model info
    print("\n📊 Model Information:")
    info = classifier.get_model_info()
    for key, value in info.items():
        print(f"  {key}: {value}")
    
    # Test cases
    test_emails = [
        {
            'subject': 'URGENT: Verify your account now!',
            'body': 'Your PayPal account has been suspended. Click here to verify immediately: http://paypa1-verify.com',
            'sender': 'security@paypa1.com'
        },
        {
            'subject': 'Meeting tomorrow at 2pm',
            'body': 'Hi team, just a reminder about our quarterly review meeting tomorrow at 2pm in conference room B.',
            'sender': 'manager@company.com'
        },
        {
            'subject': 'You won $1,000,000!',
            'body': 'Congratulations! You have been selected as the winner of our lottery. Click here to claim your prize now!',
            'sender': 'lottery@winner-claim.xyz'
        }
    ]
    
    print("\n🔍 Testing predictions:")
    print("-" * 60)
    
    for i, email in enumerate(test_emails, 1):
        print(f"\n📧 Email {i}:")
        print(f"   Subject: {email['subject']}")
        print(f"   Sender: {email['sender']}")
        
        result = classifier.predict(email)
        
        verdict = "🚨 PHISHING" if result['is_phishing'] else "✅ LEGITIMATE"
        print(f"   Verdict: {verdict}")
        print(f"   Phishing Probability: {result['phishing_probability']:.2%}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Method: {result['method']}")