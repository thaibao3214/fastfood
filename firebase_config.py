import firebase_admin
from firebase_admin import credentials

cred = credentials.Certificate("firebase_key.json")  # đường dẫn tới file JSON bạn vừa tải
firebase_admin.initialize_app(cred)
