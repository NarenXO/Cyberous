from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict, List
import bcrypt
import jwt
import datetime
from datetime import datetime as dt

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
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
SECRET_KEY = "cyberous-secret-key-2024"
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
def get_agents(trust_score: int, full_evaluation: bool = False) -> List[Dict]:
    if full_evaluation:
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
    
    if user["frozen"]:
        raise HTTPException(status_code=403, detail={"detail": "Account frozen. OTP verification required."})
    
    token = create_token(user["username"])
    
    return {
        "token": token,
        "username": user["username"],
        "balance": user["balance"],
        "trust_score": user["trust_score"],
        "agents": get_agents(user["trust_score"], full_evaluation=False)
    }

@app.post("/api/transfer")
async def transfer(request: TransferRequest, username: str = Depends(verify_token)):
    user = users_db.get(username)
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    if request.pin != user["pin"]:
        raise HTTPException(status_code=401, detail="Invalid PIN")
    
    if request.amount > user["balance"]:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Process transfer
    user["balance"] -= request.amount
    
    return {
        "decision": "grant",
        "explanation": "Transaction approved based on risk evaluation.",
        "new_balance": user["balance"],
        "agents": get_agents(user["trust_score"], full_evaluation=True)
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
