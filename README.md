# PhishGuard-
Engineered an end-to-end phishing detection system using a fine-tuned RoBERTa Transformer model, achieving high predictive accuracy by analyzing email body text for sophisticated linguistic patterns and deceptive intent.

Integrated a multi-source Threat Intelligence pipeline with VirusTotal and AbuseIPDB APIs, enabling real-time reputation lookups for extracted IOCs (IPs, URLs, and domains) and significantly reducing false positives through cross-verification.

Developed a robust Risk Scoring engine featuring a "Max Strategy" ensemble approach and critical overrides to prioritize high-risk indicators like dangerous file attachments, suspicious TLDs, and brand typosquatting attempts.

Built a scalable backend architecture with FastAPI and MySQL, implementing an automated attachment analyzer with libmagic and a threat intel caching system to optimize API usage and enhance system performance.