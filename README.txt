# FRAUDSHIELD AI — Multi-module Cyber Fraud Prototype

## Windows setup
1. Install Python 3.10 or newer.
2. Extract this ZIP.
3. Open the extracted folder in File Explorer.
4. Click the address bar, type `cmd`, and press Enter.
5. Run:

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

6. The terminal prints a local address, usually `http://localhost:8501`. Open that address in Chrome.

Keep the terminal open while using the website. Press `Ctrl+C` in the terminal to stop it.

## Modules
- Transaction risk indicator (transparent demo rules; not trained AI)
- Phishing URL heuristic checker
- Scam-message keyword screening
- Upload a labelled CSV and train a Random Forest baseline model

## Dataset requirements
For model training, upload a CSV with a fraud/genuine label column (for example `Class` or `is_fraud`) and numeric feature columns. Select the label column in the app. The trainer uses numeric columns only and reports a random holdout evaluation. Do not include direct identifiers, card numbers, CVVs, OTPs, PINs, passwords, or private customer data.

For a college experiment, a public, appropriately licensed credit-card fraud dataset can be used after checking its terms. A card dataset does not automatically train a UPI, bank-transfer, URL or message detector. Each category needs representative labelled data and its own validation.

## Important limitations
This is a local educational prototype, not a production fraud-prevention service. The URL and message modules use simple heuristics, and the generic transaction form uses illustrative rules. No bank/UPI/card network is connected. Scores are not probabilities and must not be interpreted as proof that something is safe or fraudulent.
