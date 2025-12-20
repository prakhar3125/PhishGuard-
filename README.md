# PhishGuard: Multi-Layer Email Security & Detection Pipeline
## 1. Overview
Engineered an end-to-end phishing detection system using a fine-tuned RoBERTa Transformer model, achieving high predictive accuracy by analyzing email body text for sophisticated linguistic patterns and deceptive intent.

Integrated a multi-source Threat Intelligence pipeline with VirusTotal and AbuseIPDB APIs, enabling real-time reputation lookups for extracted IOCs (IPs, URLs, and domains) and significantly reducing false positives through cross-verification.

Developed a robust Risk Scoring engine featuring a "Max Strategy" ensemble approach and critical overrides to prioritize high-risk indicators like dangerous file attachments, suspicious TLDs, and brand typosquatting attempts.

Built a scalable backend architecture with FastAPI and MySQL, implementing an automated attachment analyzer with libmagic and a threat intel caching system to optimize API usage and enhance system performance.

---

## 2. System Architecture & Detection Pipeline

The PhishGuard backend employs a multi-stage, hybrid analysis pipeline that combines static rules, external threat intelligence, and deep learning.

1.  **Ingestion & Parsing**
    * **Input:** Raw email files (`.eml`, `.msg`, `.txt`).
    * **Parsing:** The `IOCExtractor` module utilizes `email.parser.BytesParser` and `BeautifulSoup` to deconstruct the email into headers, body text, HTML structures, and attachments.

2.  **Static IOC Extraction**
    * **Pattern Matching:** High-performance Regex and `tldextract` identify potential Indicators of Compromise (IOCs):
        * **Network:** IPv4/IPv6 addresses, URLs, Domains.
        * **File:** Attachment Hashes (MD5/SHA256).
        * **Metadata:** Sender identity, Return-Path, X-Originating-IP.

3.  **Multi-Modal Threat Analysis**
    * **Threat Intelligence (Reputation):**
        * Checks extracted IOCs against **VirusTotal** and **AbuseIPDB**.
        * **Optimization:** Implements a MySQL-based `ThreatIntelCache` to serve results instantly for previously scanned entities, minimizing API latency.
    * **AI Classification (Semantic):**
        * Tokenizes email body text using Hugging Face `AutoTokenizer`.
        * Performs inference using a fine-tuned **RoBERTa Transformer** model (GPU-accelerated) to detect linguistic cues of phishing (urgency, coercion, fear).
    * **Heuristic Engine (Rules):**
        * Validates specific red flags: Suspicious TLDs (`.xyz`, `.top`), IP-based URLs, and Header Spoofing (From vs. Return-Path mismatch).

4.  **Risk Scoring & Aggregation**
    * **Weighted Logic:** Individual component scores are normalized and aggregated:
        $$FinalScore = (W_{AI} \cdot Score_{AI}) + (W_{Intel} \cdot Score_{Intel}) + (W_{Heuristic} \cdot Score_{Heuristic})$$
    * **Verdict Thresholds:**
        * 🟢 **0 - 30:** Clean
        * 🟡 **31 - 70:** Suspicious
        * 🔴 **71 - 100:** Malicious

5.  **Persistence & Response**
    * **Storage:** Verdicts and metadata are committed to the MySQL database for historical analytics.
    * **Response:** Frontend receives a JSON payload containing the final Verdict, Risk Score, and a breakdown of specific threats found.

---

## 3. Data Sourcing & Experimental Dataset

### Dataset Overview
To benchmark the PhishGuard detection engine, we utilized the **Apache SpamAssassin Public Corpus**, an industry-standard open-source collection of email messages used for training and evaluating spam filtering systems. This dataset provides raw, unmodified email files (RFC 822 format), including headers, body text, and attachments, simulating a realistic email server environment.

### Data Distribution
A stratified subset was selected to evaluate both the False Negative Rate (FNR) on malicious content and the False Positive Rate (FPR) on legitimate business communications.

| Category | Source Folder | Sample Size | Description |
| :--- | :--- | :--- | :--- |
| **Malicious (Spam)** | `20021010_spam.tar.bz2` | **501** | Phishing attempts, Nigerian Prince scams, and pharmaceutical spam. |
| **Safe (Ham)** | `20021010_easy_ham.tar.bz2` | **2552** | Legitimate business correspondence, newsletters, and personal emails. |
| **Total** | | **3053** | Total unique samples processed. |

### Preprocessing Pipeline
Before analysis, the raw corpus underwent the following preprocessing steps to match modern `.eml` standards:
1.  **Format Standardization:** Raw files were programmatically renamed with the `.eml` extension to trigger the backend's `email` policy parser.
2.  **Encoding Normalization:** Non-UTF-8 characters were sanitized to prevent parsing failures during the tokenization phase.
3.  **Parsing:** The `BytesParser` module extracted the payload (body text) for the RoBERTa model and the headers (Received, X-Originating-IP) for the Heuristic Engine.

**Source Access:** The dataset is publicly available at the [Apache SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/).

---

## 4. Quantitative Performance Analysis

### 4.1. Offline Mode Analysis (Spam Dataset)

**Experimental Configuration**
The PhishGuard detection pipeline was evaluated against a dataset of $N = 501$ confirmed real-world spam samples. The system operated in **Offline Mode** (Threat Intelligence APIs disabled) to specifically isolate and assess the efficacy of the fine-tuned RoBERTa Transformer model and the Heuristic Engine without external reputation validation.

**Operational Metrics**
* **Total Samples Processed:** 501
* **Valid Samples ($N_{valid}$):** 492 (9 failed due to connection timeouts)
* **Average Latency ($\mu$):** ~7.52 seconds/email (CPU-bound)

**Detection Efficacy**
The system's detection capability was measured using **Recall (Sensitivity)** to determine the proportion of actual threats correctly identified.

* **True Positives ($TP$):** 433 (Successfully flagged as Malicious/Suspicious)
* **False Negatives ($FN$):** 59 (Incorrectly labeled as Clean)

$$Recall = \frac{TP}{TP + FN} \times 100 = \frac{433}{492} \times 100 = \textbf{88.01\%}$$

$$False Negative Rate (FNR) = 1 - Recall = \textbf{11.99\%}$$

**Key Findings**
The system demonstrated an **88.01% detection rate** relying solely on linguistic analysis and static feature extraction. The **11.99% miss rate** primarily comprised "low-volume" phishing emails lacking overt linguistic urgency. These results indicate that while the local AI model is robust for high-confidence threats (often scoring 99/100), the integration of Threat Intelligence APIs (VirusTotal/AbuseIPDB) is essential to bridge the gap for "clean-looking" threats, potentially boosting detection rates above **95%**.

### 4.2. Offline Mode Analysis (Safe Dataset)

**Experimental Configuration**
To evaluate the system's ability to minimize false alarms, the detection pipeline was tested against a larger dataset of $N = 2552$ verified legitimate (Ham) emails. As with the spam test, the system operated in **Offline Mode**, relying exclusively on linguistic probability and heuristic analysis without access to whitelist databases or reputation APIs.

**Operational Metrics**
* **Total Samples Processed:** 2552
* **Valid Samples ($N_{valid}$):** 2522 (30 failed due to connection timeouts or parsing errors)
* **Average Latency ($\mu$):** ~7.38 seconds/email

**Classification Specificity**
For safe emails, the critical metric is **Specificity (True Negative Rate)**, which measures the system's ability to correctly ignore non-malicious content.

* **True Negatives ($TN$):** 2383 (Correctly labeled as Safe/Clean)
* **False Positives ($FP$):** 139 (Incorrectly flagged as Malicious/Suspicious)

$$Specificity = \frac{TN}{TN + FP} \times 100 = \frac{2383}{2522} \times 100 = \textbf{94.49\%}$$

$$False Positive Rate (FPR) = 1 - Specificity = \textbf{5.51\%}$$

**Key Findings**
The system achieved a **94.49% Specificity rate**, correctly filtering the vast majority of legitimate traffic. The **5.51% False Positive Rate** was primarily driven by legitimate transactional emails (e.g., password resets, urgent invoice reminders) where the linguistic patterns mirrored phishing urgency. In a production environment, enabling the Threat Intelligence module would likely resolve these errors by validating the sender's domain reputation (e.g., whitelisting `google.com` or `paypal.com`), thereby reducing the FPR to near-zero.

### 4.3. Consolidated Performance Metrics

The following table summarizes the system's performance across both malicious and benign datasets in **Offline Mode** (RoBERTa + Heuristics only).

| Metric | Malicious (Spam) | Safe (Ham) | Combined / Average |
| :--- | :---: | :---: | :---: |
| **Total Samples** | 501 | 2552 | **3053** |
| **Valid Samples ($N_{valid}$)** | 492 | 2522 | **3014** |
| **Correctly Classified** | 433 ($TP$) | 2383 ($TN$) | **2816** |
| **Misclassified** | 59 ($FN$) | 139 ($FP$) | **198** |
| **Primary Accuracy Metric** | **88.01%** (Recall) | **94.49%** (Specificity) | **93.43%** (Overall Accuracy)* |
| **Error Rate** | 11.99% (FNR) | 5.51% (FPR) | **6.57%** |
| **Avg. Latency ($\mu$)** | ~7.52s | ~7.38s | **~7.40s** |

> \* **Overall Accuracy** is calculated as $\frac{TP + TN}{Total Valid Samples} = \frac{433 + 2383}{3014} \approx 93.43\%$
>
> ---

## 5. Technology Stack

**Backend Infrastructure**
* **Language:** Python 3.9+
* **Framework:** FastAPI (High-performance async API)
* **Database:** MySQL (Persistence & Threat Intel Caching)
* **ORM:** SQLAlchemy (Database abstraction)

**AI & Machine Learning**
* **Model:** RoBERTa (Robustly Optimized BERT Pretraining Approach)
* **Library:** PyTorch & Hugging Face Transformers
* **Tokenizer:** AutoTokenizer (Pre-trained `ealvaradob/bert-finetuned-phishing`)

**Security & Analysis Tools**
* **Threat Intel:** VirusTotal API v3, AbuseIPDB API v2
* **File Analysis:** `python-magic` (MIME type validation), `olefile` (Microsoft Office macro extraction)
* **Parsing:** `BeautifulSoup4` (HTML scrubbing), `tldextract` (Domain parsing)