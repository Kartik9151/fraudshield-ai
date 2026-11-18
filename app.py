import streamlit as st
import pandas as pd
import numpy as np
import re, ipaddress
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import os 
st.set_page_config(page_title="FraudShield AI", page_icon="🛡️", layout="wide")
st.title("🛡️ FRAUDSHIELD AI")
st.caption("Multi-module cyber-fraud risk assessment | Educational and decision-support prototype")

st.warning("This tool provides risk indicators, not a definitive fraud verdict. Do not enter real card numbers, CVVs, passwords, OTPs, UPI PINs, or confidential customer data.")

with st.sidebar:
    st.header("Navigation")
    page=st.radio("Choose module",["Overview","Transaction AI","Phishing URL Checker","Message / Scam Checker","Train your own model","About & limitations"])
    st.divider()
    st.caption("Local demo • Runs on your Windows computer")

if page=="Overview":
    st.subheader("One platform, multiple fraud categories")
    cols=st.columns(4)
    for c,(n,d) in zip(cols,[("Payments","UPI, bank transfers"),("Cards","Card transaction patterns"),("URLs","Suspicious / phishing links"),("Messages","SMS, email, scam text")]):
        c.metric(n,"Module available")
        c.caption(d)
    st.markdown("### Recommended workflow")
    st.write("1. Train the transaction model using a labelled dataset you are authorised to use.")
    st.write("2. Test transaction records in the Transaction AI module.")
    st.write("3. Check suspicious links and message text in their dedicated modules.")
    st.info("UPI, bank-transfer and card fraud share transaction-risk concepts, but their datasets and feature definitions are not interchangeable. Phishing URLs and scam messages use separate checks.")

def url_check(url):
    raw=url.strip()
    if not re.match(r"^https?://",raw,re.I): raw="http://"+raw
    p=urlparse(raw); host=p.hostname or ""
    reasons=[]
    if not host: reasons.append("Could not identify a valid hostname.")
    if p.scheme!="https": reasons.append("The link does not use HTTPS.")
    try:
        ipaddress.ip_address(host); reasons.append("The address uses a raw IP instead of a domain name.")
    except: pass
    if len(host)>45: reasons.append("Unusually long hostname.")
    if host.count(".")>=4: reasons.append("Many subdomains are present.")
    if "xn--" in host.lower(): reasons.append("Internationalised/punycode domain; verify carefully.")
    if re.search(r"(login|verify|secure|account|update|banking|wallet|kyc|password)",raw,re.I):
        reasons.append("Contains login, verification, account or credential-related wording.")
    if re.search(r"@|%40",raw): reasons.append("Contains an @ symbol or encoded @, which can disguise the destination.")
    if re.search(r"(bit\.ly|tinyurl|t\.co|cutt\.ly|shorturl)",host,re.I):
        reasons.append("Uses a URL-shortening service; final destination is hidden.")
    if len(raw)>120: reasons.append("Unusually long URL.")
    score=min(100, 8*len(reasons))
    if score>=40: label="High risk"
    elif score>=16: label="Needs review"
    else: label="No obvious warning found"
    return score,label,reasons

def message_check(msg):
    rules=[
      (r"\b(otp|one.time.password|upi pin|cvv|password)\b",25,"Requests or mentions highly sensitive authentication details."),
      (r"\b(urgent|immediately|within \d+ minutes|account blocked|suspended)\b",15,"Uses urgency or account-threat language."),
      (r"\b(prize|lottery|won|winner|free gift|cashback)\b",15,"Promises a prize, reward or unusually attractive benefit."),
      (r"\b(verify|kyc|reactivate|refund|claim)\b",12,"Uses verification, KYC, refund or claim language."),
      (r"https?://|www\.",20,"Contains a web link; verify its destination independently."),
      (r"\b(send|share|tell me|provide)\b",8,"Asks the recipient to provide information.")
    ]
    score=0; reasons=[]
    for pat,pts,reason in rules:
        if re.search(pat,msg,re.I):
            score+=pts; reasons.append(reason)
    score=min(100,score)
    label="High risk" if score>=50 else ("Needs review" if score>=20 else "No obvious warning found")
    return score,label,reasons

if page=="Transaction AI":
    st.subheader("Transaction risk assessment")
    st.write("Enter non-sensitive transaction characteristics. Never enter account/card credentials.")
    with st.form("txform"):
        a,b,c=st.columns(3)
        amount=a.number_input("Amount",min_value=0.0,value=2500.0,step=100.0)
        channel=b.selectbox("Channel",["UPI","Bank transfer","Credit/debit card","Other"])
        international=c.selectbox("Cross-border transaction?",["No","Yes"])
        d,e,f=st.columns(3)
        new_device=d.selectbox("New / unrecognised device?",["No","Yes"])
        unusual_time=e.selectbox("Unusual time for customer?",["No","Yes"])
        rapid=f.selectbox("Multiple rapid transactions?",["No","Yes"])
        merchant=st.selectbox("Merchant / beneficiary familiarity",["Known","Unknown","Not applicable"])
        submitted=st.form_submit_button("Assess transaction risk")
    if submitted:
        model_path=os.path.join(os.path.dirname(__file__),"fraud_model.joblib")
        if os.path.exists(model_path):
            model=joblib.load(model_path)
            st.info("A trained dataset model is available, but its input features may not match this generic form. Use the model's own feature columns in the Train your own model tab; this form still provides a separate transparent indicator score.")
        points=(20 if amount>50000 else 10 if amount>20000 else 0)+(20 if international=="Yes" else 0)+(20 if new_device=="Yes" else 0)+(15 if unusual_time=="Yes" else 0)+(25 if rapid=="Yes" else 0)+(15 if merchant=="Unknown" else 0)
        score=min(points,100)
        label="High risk" if score>=60 else ("Needs review" if score>=30 else "Lower risk")
        st.metric("Rule-based risk indicator",f"{score}/100",label)
        st.write("**Reasons to review**")
        reasons=[]
        if amount>20000: reasons.append("Higher transaction amount under this demo rule.")
        if international=="Yes": reasons.append("Cross-border transaction.")
        if new_device=="Yes": reasons.append("New or unrecognised device.")
        if unusual_time=="Yes": reasons.append("Unusual transaction time.")
        if rapid=="Yes": reasons.append("Rapid transaction pattern.")
        if merchant=="Unknown": reasons.append("Unknown merchant or beneficiary.")
        if reasons:
            for r in reasons: st.write("• "+r)
        else: st.write("No selected warning indicators.")
        st.caption("This is a transparent demonstration score, not an AI prediction or bank-grade fraud decision. Thresholds are illustrative and require validation.")

elif page=="Phishing URL Checker":
    st.subheader("Phishing URL risk checker")
    url=st.text_input("Paste a URL (do not open it)",placeholder="https://example.com")
    if st.button("Check URL",type="primary") and url.strip():
        score,label,reasons=url_check(url)
        st.metric("URL warning score",f"{score}/100",label)
        if reasons:
            for r in reasons: st.write("• "+r)
        else: st.success("No obvious warning indicators were found by these simple checks.")
        st.caption("Heuristic screening only. It does not visit the website, verify ownership, inspect page content, or prove a URL is safe.")

elif page=="Message / Scam Checker":
    st.subheader("SMS, email and message scam screening")
    msg=st.text_area("Paste suspicious message text",height=180,placeholder="Paste message text here. Remove names, phone numbers and private details.")
    if st.button("Analyse message",type="primary") and msg.strip():
        score,label,reasons=message_check(msg)
        st.metric("Message warning score",f"{score}/100",label)
        if reasons:
            for r in reasons: st.write("• "+r)
        else: st.success("No obvious warning phrases were detected.")
        st.caption("Keyword-based screening can miss new scams and can flag legitimate messages. Never share OTP, PIN, CVV or passwords.")

elif page=="Train your own model":
    st.subheader("Train a transaction model using a labelled CSV")
    st.write("Upload a dataset you are authorised to use. The file must contain a target column identifying fraud vs genuine transactions.")
    file=st.file_uploader("Upload CSV",type=["csv"])
    if file:
        try:
            df=pd.read_csv(file)
            st.write("Preview",df.head(8))
            target=st.selectbox("Choose target / label column",df.columns)
            st.write("Target values:",df[target].astype(str).value_counts().head(10))
            if st.button("Train Random Forest",type="primary"):
                data=df.dropna(subset=[target]).copy()
                y=data[target].astype(str)
                if y.nunique()<2: st.error("Target column must contain at least two classes.")
                else:
                    X=data.drop(columns=[target]).select_dtypes(include=[np.number]).replace([np.inf,-np.inf],np.nan)
                    X=X.fillna(X.median(numeric_only=True)).fillna(0)
                    if X.shape[1]<1: st.error("No numeric feature columns found. Prepare numeric features first.")
                    else:
                        le=LabelEncoder(); yy=le.fit_transform(y)
                        strat=yy if min(np.bincount(yy))>=2 else None
                        Xtr,Xte,ytr,yte=train_test_split(X,yy,test_size=.2,random_state=42,stratify=strat)
                        clf=RandomForestClassifier(n_estimators=250,class_weight="balanced",random_state=42,n_jobs=-1)
                        clf.fit(Xtr,ytr); pred=clf.predict(Xte)
                        st.success("Model training and holdout evaluation completed.")
                        m1,m2,m3,m4=st.columns(4)
                        m1.metric("Accuracy",f"{accuracy_score(yte,pred):.3f}")
                        m2.metric("Precision",f"{precision_score(yte,pred,average='weighted',zero_division=0):.3f}")
                        m3.metric("Recall",f"{recall_score(yte,pred,average='weighted',zero_division=0):.3f}")
                        m4.metric("F1 score",f"{f1_score(yte,pred,average='weighted',zero_division=0):.3f}")
                        st.write("Confusion matrix")
                        st.dataframe(pd.DataFrame(confusion_matrix(yte,pred),index=[f"Actual {x}" for x in le.classes_],columns=[f"Predicted {x}" for x in le.classes_]))
                        payload={"model":clf,"features":list(X.columns),"encoder":le,"classes":list(le.classes_)}
                        st.download_button("Download trained model",joblib.dumps(payload) if hasattr(joblib,"dumps") else __import__("pickle").dumps(payload),"fraudshield_model.pkl","application/octet-stream")
                        st.info("The model uses numeric columns only. Remove identifiers and leakage columns before training. Use a time-based split for realistic deployment evaluation; this random split is a classroom baseline.")
        except Exception as e: st.error(f"Could not read/train this file: {e}")

elif page=="About & limitations":
    st.subheader("What this prototype can and cannot do")
    st.markdown("""
**Included**
- Separate screening modules for transaction characteristics, URLs and scam messages.
- CSV upload and Random Forest training on labelled numeric transaction datasets.
- Holdout metrics and confusion matrix.

**Not included / not claimed**
- Direct connection to banks, UPI networks, card processors, SMS providers or live transaction feeds.
- Guaranteed detection, real-time blocking, identity verification or regulatory certification.
- A single universal model for every fraud category.

**For a serious real-world deployment**
1. Use permissioned, representative, labelled data for each fraud category.
2. Validate with time-based and external test sets; measure precision, recall, PR-AUC and false-positive rate.
3. Add secure authentication, encryption, audit logs, rate limits and privacy controls.
4. Keep a human review process and monitor model drift.
""")
