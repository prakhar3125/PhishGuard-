#!/usr/bin/env python3
"""
Train PhishGuard ML Model
Supports both traditional ML and transformer models
"""

import argparse
from app.core.ml_classifier import PhishingClassifier

def load_sample_dataset():
    """Load sample phishing dataset for training"""
    
    # Sample legitimate emails
    legitimate_emails = [
        "Meeting scheduled for tomorrow at 2 PM in conference room A",
        "Please review the attached quarterly report by end of week",
        "Reminder: Team lunch on Friday at the new Italian restaurant",
        "Your package has been delivered. Thank you for your order",
        "Weekly newsletter: Top 10 productivity tips for remote work",
        "Project update: Phase 1 completed successfully, moving to Phase 2",
        "Thank you for attending yesterday's webinar",
        "Your subscription will renew next month",
        "New features added to your favorite app",
        "Company holiday schedule for next month"
    ]
    
    # Sample phishing emails
    phishing_emails = [
        "URGENT: Your account has been suspended. Verify immediately at http://fake-paypal.com",
        "Congratulations! You've won $1,000,000. Click here to claim your prize NOW",
        "Your PayPal account requires immediate action. Login here: bit.ly/abc123",
        "ALERT: Unusual activity detected. Confirm your identity to unlock account",
        "Your bank account will be closed unless you update information immediately",
        "IRS Tax Refund: You are eligible for $2,500 refund. Act now!",
        "Your password will expire today. Reset it here to avoid account suspension",
        "Security Alert: Someone tried to access your account. Verify now!",
        "Click here to update your payment information and continue service",
        "Limited time offer! Get iPhone 15 for $99. Hurry, only 5 left!"
    ]
    
    # Combine and create labels
    emails = legitimate_emails + phishing_emails
    labels = [0] * len(legitimate_emails) + [1] * len(phishing_emails)
    
    return emails, labels

def main():
    parser = argparse.ArgumentParser(description='Train PhishGuard ML Model')
    parser.add_argument('--model-type', choices=['transformer', 'traditional', 'both'], 
                       default='transformer', help='Model type to train')
    parser.add_argument('--epochs', type=int, default=3, help='Training epochs (transformer only)')
    parser.add_argument('--batch-size', type=int, default=8, help='Batch size (transformer only)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("PhishGuard Model Training")
    print("=" * 60)
    
    # Load dataset
    print("\n📚 Loading training dataset...")
    emails, labels = load_sample_dataset()
    print(f"  ✓ Loaded {len(emails)} emails ({sum(labels)} phishing, {len(labels) - sum(labels)} legitimate)")
    
    # Train transformer
    if args.model_type in ['transformer', 'both']:
        print("\n🤖 Training Transformer Model...")
        classifier = PhishingClassifier(use_transformer=True)
        classifier.train_transformer(
            emails, 
            labels, 
            epochs=args.epochs,
            batch_size=args.batch_size
        )
    
    # Train traditional
    if args.model_type in ['traditional', 'both']:
        print("\n🌲 Training Traditional ML Model...")
        classifier = PhishingClassifier(use_transformer=False)
        classifier.train_traditional(emails, labels)
    
    print("\n" + "=" * 60)
    print("✓ Training Complete!")
    print("=" * 60)
    print("\nModels saved in ./models/ directory")
    print("You can now run: python -m app.main")

if __name__ == "__main__":
    main()