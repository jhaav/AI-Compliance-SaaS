from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import sqlite3
import jwt
import datetime
import os

# Secure secret key for JWT authentication
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")

app = FastAPI()

# Database Setup
def init_db():
    conn = sqlite3.connect("risk_compliance.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_details TEXT,
            risk_score INTEGER,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Risk Model
class Transaction(BaseModel):
    transaction_details: str

# Token Authentication
def create_token(username: str):
    payload = {"sub": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# AI-Based Risk Assessment
def assess_risk(details: str):
    high_risk_words = ["fraud", "scam", "illegal", "suspicious", "money laundering", "bribe"]
    risk_score = sum([details.lower().count(word) * 20 for word in high_risk_words])
    return min(risk_score, 100)

@app.post("/login/")
def login(username: str, password: str):
    if username == "admin" and password == "password":
        return {"token": create_token(username)}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/assess-risk/"
