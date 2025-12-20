import os
import requests
import time
import csv
from concurrent.futures import ThreadPoolExecutor

# ================= CONFIGURATION =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# ONLY SPAM FOLDER
SPAM_FOLDER = os.path.join(BASE_DIR, "testcase", "spam")

API_URL = "http://localhost:8000/api/v1/analyze"
OUTPUT_CSV = "spam_test_results.csv"
MAX_WORKERS =  1
# =================================================

def analyze_email(file_path):
    """Sends a single email to the API and returns the result."""
    file_name = os.path.basename(file_path)
    expected_label = 'SPAM' # We know this is the spam folder

    try:
        with open(file_path, 'rb') as f:
            files = {'file': (file_name, f, 'message/rfc822')}
            start_time = time.time()
            # Send to API
            response = requests.post(API_URL, files=files, timeout=30)
            duration = time.time() - start_time

        if response.status_code == 200:
            data = response.json()
            verdict = data.get('verdict', 'UNKNOWN')
            score = data.get('risk_score', 0)
            
            # Logic: MALICIOUS/SUSPICIOUS = SPAM
            predicted_label = 'SPAM' if verdict in ['MALICIOUS', 'SUSPICIOUS'] else 'HAM'
            is_correct = (expected_label == predicted_label)
            icon = '✅' if is_correct else '❌'
            
            print(f"{icon} {file_name[:25]:<25} | Pred: {verdict:<10} ({score}) | {duration:.2f}s")
            
            return {
                'file': file_name,
                'expected': expected_label,
                'predicted': predicted_label,
                'verdict': verdict,
                'score': score,
                'correct': is_correct,
                'status': 'SUCCESS'
            }
        else:
            print(f"⚠️ {file_name} | API Error: {response.status_code}")
            return {'file': file_name, 'status': 'API_ERROR'}
            
    except Exception as e:
        print(f"❌ {file_name} | Failed: {str(e)}")
        return {'file': file_name, 'status': 'CONNECTION_ERROR'}

def process_folder(folder_path):
    files = []
    if not os.path.exists(folder_path):
        print(f"❌ Folder not found: {folder_path}")
        return files
    for f in os.listdir(folder_path):
        if os.path.isfile(os.path.join(folder_path, f)):
            files.append(os.path.join(folder_path, f))
    return files

def main():
    print("\n" + "="*50)
    print("🚀 SPAM-ONLY BATCH TESTER")
    print("="*50)
    print(f"📂 Spam Folder: {SPAM_FOLDER}")
    
    spam_files = process_folder(SPAM_FOLDER)
    
    if not spam_files:
        print("❌ No files found in Spam folder!")
        return

    print(f"📦 Found {len(spam_files)} Spam emails.")
    print(f"⚡ Starting analysis (Threat Intel SKIP Mode)...")

    results = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(analyze_email, f) for f in spam_files]
        for future in futures:
            results.append(future.result())

    successful_runs = [r for r in results if r.get('status') == 'SUCCESS']
    
    if successful_runs:
        tp = sum(1 for r in successful_runs if r['predicted'] == 'SPAM')
        fn = sum(1 for r in successful_runs if r['predicted'] == 'HAM') # Missed phishing
        total = len(successful_runs)
        recall = (tp / total * 100) if total > 0 else 0
        
        print("\n" + "="*50)
        print("📊 SPAM DETECTION REPORT")
        print("="*50)
        print(f"✅ Detection Rate: {recall:.2f}%")
        print(f"Caught: {tp} | Missed: {fn}")
        print("="*50)

if __name__ == "__main__":
    main()