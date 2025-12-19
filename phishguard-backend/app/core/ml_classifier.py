import joblib
import numpy as np
import re
from typing import Dict, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
import os

class PhishingClassifier:
    def __init__(self, model_path: str = './models/phishing_model.pkl'):
        self.model_path = model_path
        self.vectorizer_path = './models/vectorizer.pkl'
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        
        # Load model if exists
        if os.path.exists(model_path) and os.path.exists(self.vectorizer_path):
            self.load_model()
    
    def load_model(self):
        """Load pre-trained model and vectorizer"""
        try:
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)
            self.is_trained = True
            print("✓ ML Model loaded successfully")
        except Exception as e:
            print(f"✗ Error loading model: {e}")
            self.is_trained = False
    
    def train(self, emails: list, labels: list):
        """Train the phishing classifier"""
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
        
        # Train model (Random Forest for better performance)
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X, labels)
        
        # Save model
        os.makedirs('./models', exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.vectorizer, self.vectorizer_path)
        
        self.is_trained = True
        print("✓ Model trained and saved successfully")
    
    def predict(self, email_content: Dict) -> Dict:
        """Predict if email is phishing"""
        if not self.is_trained:
            return self._heuristic_prediction(email_content)
        
        try:
            # Prepare email text
            email_text = self._prepare_email_text(email_content)
            
            # Transform and predict
            X = self.vectorizer.transform([email_text])
            prediction = self.model.predict(X)[0]
            proba = self.model.predict_proba(X)[0]
            
            return {
                'is_phishing': bool(prediction),
                'phishing_probability': float(proba[1]),
                'confidence': float(max(proba)),
                'method': 'ml_model'
            }
        
        except Exception as e:
            print(f"ML prediction error: {e}")
            return self._heuristic_prediction(email_content)
    
    def _prepare_email_text(self, email_content: Dict) -> str:
        """Prepare email content for ML prediction"""
        parts = []
        
        if email_content.get('subject'):
            parts.append(email_content['subject'])
        
        if email_content.get('body'):
            parts.append(email_content['body'])
        
        if email_content.get('sender'):
            parts.append(email_content['sender'])
        
        return ' '.join(parts)
    
    def _heuristic_prediction(self, email_content: Dict) -> Dict:
        """Fallback heuristic-based prediction when ML model not available"""
        score = 0
        indicators = []
        
        subject = email_content.get('subject', '').lower()
        body = email_content.get('body', '').lower()
        sender = email_content.get('sender', '').lower()
        
        # Phishing keywords in subject
        phishing_keywords = [
            'urgent', 'verify', 'suspended', 'unusual activity',
            'confirm your account', 'security alert', 'locked',
            'update payment', 'prize', 'winner', 'congratulations',
            'click here', 'act now', 'limited time'
        ]
        
        for keyword in phishing_keywords:
            if keyword in subject:
                score += 15
                indicators.append(f'Suspicious keyword in subject: {keyword}')
        
        # Check for urgency language
        urgency_words = ['urgent', 'immediate', 'action required', 'asap', 'now']
        urgency_count = sum(1 for word in urgency_words if word in subject or word in body)
        if urgency_count > 0:
            score += urgency_count * 10
            indicators.append('Uses urgency tactics')
        
        # Check for request for credentials
        credential_words = ['password', 'username', 'login', 'account', 'verify', 'confirm']
        credential_count = sum(1 for word in credential_words if word in body)
        if credential_count >= 2:
            score += 20
            indicators.append('Requests credentials or verification')
        
        # Check sender domain mismatch
        if '@' in sender:
            sender_domain = sender.split('@')[1] if '@' in sender else ''
            if sender_domain and any(brand in sender_domain for brand in ['paypal', 'amazon', 'microsoft', 'google']):
                # Check if it's not the official domain
                official_domains = ['paypal.com', 'amazon.com', 'microsoft.com', 'google.com']
                if not any(sender_domain.endswith(official) for official in official_domains):
                    score += 30
                    indicators.append('Sender domain impersonating known brand')
        
        # Normalize score to probability
        probability = min(score / 100, 1.0)
        
        return {
            'is_phishing': probability > 0.5,
            'phishing_probability': probability,
            'confidence': 0.6,  # Lower confidence for heuristic
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
        
        return features