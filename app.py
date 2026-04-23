from flask import Flask, render_template, request
import pickle
import pandas as pd
from feature_extraction import extract_features
import os

app = Flask(__name__)

model = pickle.load(open("phishing_model.pkl", "rb"))

@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        url = request.form["url"]

        # Rule-based check
        if "@" in url or "login" in url or "verify" in url or ".xyz" in url:
            result = "⚠️ Phishing Website (rule-based)"
        else:
            features = extract_features(url)
            df = pd.DataFrame([features])
            prediction = model.predict(df)

            if prediction[0] == 1:
                result = "⚠️ Phishing Website (ML)"
            else:
                result = "✅ Legitimate Website"

    return render_template("index.html", result=result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
