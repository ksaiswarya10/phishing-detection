import whois
from datetime import datetime
import re


def get_domain_age(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        w = whois.whois(domain)

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = (datetime.now() - creation_date).days

        if age_days < 180:
            return -1   # suspicious
        else:
            return 1    # safe

    except:
        return -1


def extract_features(url):
    features = {}

    # 1. SFH
    features['SFH'] = -1 if "@" in url else 1

    # 2. popUpWindow
    features['popUpWidnow'] = 1

    # 3. SSLfinal_State
    features['SSLfinal_State'] = 1 if "https" in url else -1

    # 4. Request_URL
    features['Request_URL'] = -1 if url.count('.') > 3 else 1

    # 5. URL_of_Anchor
    features['URL_of_Anchor'] = -1 if "@" in url else 1

    # 6. web_traffic
    features['web_traffic'] = 1

    # 7. URL_Length
    if len(url) < 54:
        features['URL_Length'] = 1
    elif len(url) <= 75:
        features['URL_Length'] = 0
    else:
        features['URL_Length'] = -1

    # 🔥 REPLACE THIS LINE
    features['age_of_domain'] = get_domain_age(url)

    # 9. having_IP_Address
    features['having_IP_Address'] = -1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 1

    return features