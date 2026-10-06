# Phishing URL Detector
Rule-based URL risk scorer. Standard library only (Python 3.9+).

```bash
python phishing_detector.py https://example.com "http://paypal-login.example.xyz/verify"
python phishing_detector.py --file urls.txt --json
python -m unittest -v
```
Exit code is `1` when any URL is rated High risk, so it can gate CI or mail pipelines.
Scores: <25 Low risk, 25-49 Suspicious, 50+ High risk. Heuristics are advisory, not a replacement for threat-intel feeds.
