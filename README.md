# FiShield – Real-Time Phishing URL Detection Extension

## Quick Start

### 1. Install dependencies
```bash
pip install scikit-learn pandas numpy joblib
```

### 2. (Optional but recommended) Download the dataset
Get it from: https://www.kaggle.com/datasets/suryaprabha19/phishing-url  
Place the CSV file as `phishing_urls.csv` in the same directory as `build_fishield_extension.py`

### 3. Run the builder
```bash
python build_fishield_extension.py
```
This trains the model and generates the `fishield_extension/` folder.

### 4. Load in Chrome
1. Open Chrome → go to `chrome://extensions`
2. Enable **Developer Mode** (top right toggle)
3. Click **"Load unpacked"**
4. Select the `fishield_extension/` folder

### 5. Use it!
- Visit any website — FiShield intercepts every navigation automatically
- If a URL is **Phishing** or **Suspicious**, a full-screen alert appears instantly
- The popup badge shows ✓ (safe), ! (alert)
- Click the 🛡️ extension icon to see the detailed verdict for the current page

---

## Architecture

```
fishield_extension/
├── manifest.json          ← Chrome extension config (MV3)
├── background.js          ← Service worker: intercepts navigations, runs ML
├── content.js             ← Injects alert overlay into pages  
├── popup.html / popup.js  ← Extension popup UI
├── feature_extractor.js   ← 20-feature URL heuristics (mirrors Python)
├── model_inference.js     ← Random Forest inference (browser-native JS)
├── model.json             ← Trained RF model exported as JSON trees
└── icons/                 ← Extension icons
```

## Features Extracted (20 total)

| # | Feature | Description |
|---|---------|-------------|
| 1 | url_length | Normalized URL length |
| 2 | hostname_length | Domain name length |
| 3 | path_length | URL path length |
| 4 | hyphen_density | Hyphens per character |
| 5 | dot_density | Dots per character |
| 6 | has_at_symbol | Presence of @ (credential theft) |
| 7 | double_slash | Redirect indicator |
| 8 | digit_ratio_host | Numbers in hostname (IP-like) |
| 9 | special_char_ratio | Obfuscation characters |
| 10 | suspicious_tld | Free/abused TLDs |
| 11 | excessive_subdomains | Too many subdomain levels |
| 12 | ip_as_host | IP address used instead of domain |
| 13 | brand_keyword_density | Brand name abuse |
| 14 | deceptive_domain_words | secure/login/verify in domain |
| 15 | url_encoding_ratio | %xx encoding obfuscation |
| 16 | domain_entropy | Shannon entropy → DGA detection |
| 17 | long_query_string | Unusually long query |
| 18 | many_query_params | Too many parameters |
| 19 | uses_https | HTTPS is legitimate signal |
| 20 | many_hyphens_hostname | Hyphenated domain abuse |

## Verdict Thresholds

| Confidence | Verdict |
|-----------|---------|
| ≥ 70% | 🔴 PHISHING |
| 40–69% | 🟠 SUSPICIOUS |
| < 40% | 🟢 SAFE |

## Performance Notes
- Inference runs entirely in the browser (no server needed)
- < 5ms per URL classification
- Model: Random Forest, 50 trees, max depth 8
- Re-train with full Kaggle dataset for production accuracy