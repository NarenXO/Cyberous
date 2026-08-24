from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict, List
import bcrypt
import jwt
import datetime
import os
from datetime import datetime as dt
from dotenv import load_dotenv
from services.risk_engine import calculate_trust_score, evaluate_transfer_risk

# Load environment variables
load_dotenv()

app = FastAPI()

# CORS middleware
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "cyberous-secret-key-2024")
ALGORITHM = "HS256"

# Security
security = HTTPBearer()

# In-memory database
users_db = {
    "alice": {
        "username": "alice",
        "password": hash_password("password123"),
        "balance": 12450.00,
        "pin": "1234",
        "frozen": False,
        "trust_score": 82
    },
    "attacker": {
        "username": "attacker",
        "password": hash_password("password123"),
        "balance": 0.00,
        "pin": "0000",
        "frozen": False,
        "trust_score": 23
    }
}

# Mock transaction history
transactions_db = [
    {"id": 1, "type": "credit", "amount": 5000, "recipient": "Salary", "timestamp": "2025-01-15 09:30"},
    {"id": 2, "type": "debit", "amount": 1200, "recipient": "Rent", "timestamp": "2025-01-14 14:00"}
]

# Mock trust history
trust_history_db = [
    {"login_time": "Mon 9:00 AM", "score": 85},
    {"login_time": "Tue 8:45 AM", "score": 82},
    {"login_time": "Wed 9:10 AM", "score": 88},
    {"login_time": "Thu 2:30 AM", "score": 23},
    {"login_time": "Now", "score": 82}
]

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str
    cyberous_enabled: bool
    behavior_data: Optional[Dict] = None

class TransferRequest(BaseModel):
    amount: float
    recipient: str
    pin: str

class VerifyOtpRequest(BaseModel):
    otp: str

# JWT functions
def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Helper function to get agents array
def get_agents(trust_score: int, full_evaluation: bool = False, risk_evaluation: Optional[Dict] = None) -> List[Dict]:
    if full_evaluation and risk_evaluation:
        return [
            {"name": "Signal Collector", "score": risk_evaluation["signal_collector_score"], "status": "done"},
            {"name": "Correlation Agent", "score": risk_evaluation["correlation_score"], "status": "done"},
            {"name": "Behavior Trail", "score": risk_evaluation["behavior_trail_score"], "status": "done"},
            {"name": "Decision Agent", "score": risk_evaluation["decision_score"], "status": "done"},
            {"name": "Explainer Agent", "score": risk_evaluation["explainer_score"], "status": "done"}
        ]
    elif full_evaluation:
        return [
            {"name": "Signal Collector", "score": 100, "status": "done"},
            {"name": "Correlation Agent", "score": trust_score, "status": "done"},
            {"name": "Behavior Trail", "score": 15, "status": "done"},
            {"name": "Decision Agent", "score": 20, "status": "done"},
            {"name": "Explainer Agent", "score": 100, "status": "done"}
        ]
    else:
        return [
            {"name": "Signal Collector", "score": 100, "status": "done"},
            {"name": "Correlation Agent", "score": trust_score, "status": "done"},
            {"name": "Behavior Trail", "score": None, "status": "waiting"},
            {"name": "Decision Agent", "score": None, "status": "waiting"},
            {"name": "Explainer Agent", "score": None, "status": "waiting"}
        ]

# Endpoints
@app.post("/api/login")
async def login(request: LoginRequest):
    user = users_db.get(request.username)
    
    if not user or not verify_password(request.password, user["password"]):
        raise HTTPException(status_code=401, detail={"detail": "Invalid credentials"})
    
    # Check if account is already frozen before evaluating new trust score
    if user["frozen"]:
        raise HTTPException(status_code=403, detail={"detail": "Account frozen. OTP verification required."})
    
    # Calculate dynamic trust score based on behavioral biometrics
    trust_score = calculate_trust_score(request.behavior_data, request.cyberous_enabled)
    
    # Update user's trust score in database
    user["trust_score"] = trust_score
    
    # Freeze account if trust score is below 40
    if trust_score < 40:
        user["frozen"] = True
        raise HTTPException(status_code=403, detail={"detail": "Account frozen. OTP verification required."})
    
    token = create_token(user["username"])
    
    return {
        "token": token,
        "username": user["username"],
        "balance": user["balance"],
        "trust_score": trust_score,
        "agents": get_agents(trust_score, full_evaluation=False)
    }

@app.post("/api/transfer")
async def transfer(request: TransferRequest, username: str = Depends(verify_token)):
    user = users_db.get(username)
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    if request.pin != user["pin"]:
        raise HTTPException(status_code=400, detail="Invalid PIN")
    
    if request.amount > user["balance"]:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Evaluate transfer risk using risk engine
    risk_evaluation = evaluate_transfer_risk(request.amount, user["trust_score"], user["balance"])
    
    # Process transfer only if decision is "grant"
    if risk_evaluation["decision"] == "grant":
        user["balance"] -= request.amount
    
    # Freeze account if decision is "freeze"
    if risk_evaluation["decision"] == "freeze":
        user["frozen"] = True
    
    return {
        "decision": risk_evaluation["decision"],
        "explanation": risk_evaluation["explanation"],
        "new_balance": user["balance"],
        "agents": get_agents(user["trust_score"], full_evaluation=True, risk_evaluation=risk_evaluation)
    }

@app.post("/api/verify-otp")
async def verify_otp(request: VerifyOtpRequest, username: str = Depends(verify_token)):
    user = users_db.get(username)
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Mock OTP verification - accept any 6-digit OTP
    if len(request.otp) != 6 or not request.otp.isdigit():
        raise HTTPException(status_code=400, detail="Invalid OTP format")
    
    # Unfreeze account if frozen
    user["frozen"] = False
    
    new_token = create_token(user["username"])
    
    return {
        "success": True,
        "new_token": new_token
    }

@app.get("/api/transactions")
async def get_transactions(username: str = Depends(verify_token)):
    return {"transactions": transactions_db}

@app.get("/api/trust-history")
async def get_trust_history(username: str = Depends(verify_token)):
    return {"history": trust_history_db}

@app.get("/health")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
