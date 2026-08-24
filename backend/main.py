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
from services.risk_engine import calculate_trust_score, evaluate_transfer_risk, is_attack_detected

# Load environment variables
load_dotenv()

app = FastAPI()

# CORS middleware
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
if "*" in allowed_origins or os.getenv("ALLOW_ALL_ORIGINS", "false").lower() == "true":
    allowed_origins = ["*"]
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
    "naren": {
        "username": "naren",
        "password": hash_password("password123"),
        "balance": 12450.00,
        "pin": "1234",
        "frozen": False,
        "trust_score": 82
    },
    "salman": {
        "username": "salman",
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

# Per-user trust history (max 8 entries per user)
trust_history_db = {
    "naren": [
        {"login_time": "Mon 9:00 AM", "score": 85},
        {"login_time": "Tue 8:45 AM", "score": 82},
        {"login_time": "Wed 9:10 AM", "score": 88},
        {"login_time": "Thu 2:30 AM", "score": 23},
        {"login_time": "Now", "score": 82}
    ],
    "salman": [
        {"login_time": "Mon 10:00 AM", "score": 23},
        {"login_time": "Tue 11:30 AM", "score": 25},
        {"login_time": "Now", "score": 23}
    ]
}

# Audit logs storage
audit_logs_db = []
audit_log_id_counter = 0

# Pydantic models
class BehaviorData(BaseModel):
    avg_keystroke_interval: Optional[float] = None
    avg_hold_duration: Optional[float] = None
    avg_mouse_velocity: Optional[float] = None
    ip_address: str = "127.0.0.1"
    location: str = "Local Baseline"
    device_type: str = "Desktop"
    is_attack_simulation: Optional[bool] = False

class LoginRequest(BaseModel):
    username: str
    password: str
    cyberous_enabled: bool
    behavior_data: Optional[BehaviorData] = None

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
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def add_audit_log(username: str, event: str, detail: str, severity: str = "info"):
    """Add an audit log entry"""
    global audit_log_id_counter
    audit_log_id_counter += 1
    timestamp = dt.now().strftime("%I:%M %p")
    
    log_entry = {
        "id": audit_log_id_counter,
        "timestamp": timestamp,
        "username": username,
        "event": event,
        "detail": detail,
        "severity": severity
    }
    
    audit_logs_db.insert(0, log_entry)
    
    # Keep only latest 50 logs
    if len(audit_logs_db) > 50:
        audit_logs_db.pop()

def add_trust_history(username: str, trust_score: int):
    """Add a trust history entry for a user (max 8 entries)"""
    if username not in trust_history_db:
        trust_history_db[username] = []
    
    timestamp = dt.now().strftime("%I:%M %p")
    trust_history_db[username].append({"login_time": timestamp, "score": trust_score})
    
    # Keep only last 8 entries
    if len(trust_history_db[username]) > 8:
        trust_history_db[username] = trust_history_db[username][-8:]

# Helper function to get agents array with dynamic insights
def get_agents(trust_score: int, full_evaluation: bool = False, risk_evaluation: Optional[Dict] = None, behavior_data: Optional[Dict] = None, decision: str = "grant") -> List[Dict]:
    import random
    import time
    
    # Generate Signal Collector insight
    def get_signal_collector_insight(data: Optional[Dict], is_attack: bool) -> tuple:
        latency = random.randint(4, 10)
        if is_attack:
            insight = f"Rapid submit detected. 0ms field fill. paste_events=high. IP {data.get('ip_address', 'unknown')} | {data.get('location', 'Unknown')} | {data.get('device_type', 'Unknown')}"
            score = 15
            status = "alert"
        elif data:
            keystrokes = data.get('avg_keystroke_interval', 125)
            hold = data.get('avg_hold_duration', 85)
            mouse = data.get('avg_mouse_velocity', 2.5)
            insight = f"Captured 18 keystrokes ({keystrokes}ms avg), hold {hold}ms, mouse {mouse}. IP {data.get('ip_address', '127.0.0.1')} | {data.get('location', 'Local Baseline')} | {data.get('device_type', 'Desktop')} | paste_events=0"
            score = 100
            status = "done"
        else:
            insight = "No behavioral data collected."
            score = 100
            status = "done"
        return insight, score, status, latency
    
    # Generate Correlation Agent insight
    def get_correlation_insight(data: Optional[Dict], trust_score: int, is_attack: bool) -> tuple:
        latency = random.randint(10, 20)
        if is_attack:
            insight = "Typing rhythm deviation: +95%. Mouse trajectory deviation: +80%. Geo match: untrusted. Device fingerprint: unknown."
            score = 15
            status = "alert"
        elif data:
            keystroke_dev = abs(data.get('avg_keystroke_interval', 125) - 125) / 125 * 100
            mouse_dev = abs(data.get('avg_mouse_velocity', 2.5) - 2.5) / 2.5 * 100
            geo_match = "trusted" if data.get('location', 'Local Baseline') in ["Local Baseline", "Home", "Office", "Known Location"] else "untrusted"
            insight = f"Typing rhythm deviation: +{keystroke_dev:.0f}%. Mouse trajectory deviation: +{mouse_dev:.0f}%. Geo match: {geo_match}. Device fingerprint: known."
            score = trust_score
            status = "done"
        else:
            insight = "Insufficient data for correlation analysis."
            score = trust_score
            status = "done"
        return insight, score, status, latency
    
    # Generate Behavior Trail insight
    def get_behavior_trail_insight(is_attack: bool) -> tuple:
        latency = random.randint(8, 15)
        if is_attack:
            insight = "Instant Credential Injection Detected (0ms field fill). Impossible Travel / rapid session anomaly flagged. Analyzed Signal Collector events -> flagged anomaly -> passed threat level to Decision Agent."
            score = 15
            status = "alert"
        else:
            insight = "Clean session history. No automated patterns. Analyzed Signal Collector events -> normal behavior -> passed to Decision Agent."
            score = 100
            status = "done"
        return insight, score, status, latency
    
    # Generate Decision Agent insight
    def get_decision_insight(decision: str, trust_score: int, is_attack: bool) -> tuple:
        latency = random.randint(3, 8)
        if is_attack:
            insight = "Critical risk. Action: FREEZE ACCOUNT"
            score = 15
            status = "alert"
        elif decision == "grant":
            insight = "Risk threshold met. Action: ALLOW"
            score = 100
            status = "done"
        elif decision == "verify":
            insight = "Moderate risk. Action: STEP-UP OTP"
            score = trust_score
            status = "verify"
        else:
            insight = "Critical risk. Action: FREEZE ACCOUNT"
            score = 15
            status = "alert"
        return insight, score, status, latency
    
    # Generate Explainer Agent insight (dual-tone)
    async def get_explainer_insight(decision: str, trust_score: int, is_attack: bool) -> tuple:
        start_time = time.time()
        if is_attack:
            insight = "Customer: Your account has been frozen due to suspicious automated activity. | Technical: Automated bot behavior / rapid credential injection detected. Account frozen immediately."
            score = 15
            status = "alert"
        else:
            # Try to get Grok explanation
            grok_explanation = await get_grok_explanation(decision, trust_score)
            if "Transaction approved" in grok_explanation or "Normal" in grok_explanation:
                insight = f"Customer: Your login looks normal and has been approved. | Technical: {grok_explanation}"
            elif "OTP" in grok_explanation or "verify" in grok_explanation.lower():
                insight = f"Customer: We need to verify your identity with a one-time code. | Technical: {grok_explanation}"
            else:
                insight = f"Customer: {grok_explanation} | Technical: Behavioral biometrics analysis completed."
            score = 100
            status = "done"
        latency = int((time.time() - start_time) * 1000) + random.randint(120, 250)
        return insight, score, status, latency
    
    # Check if attack detected
    is_attack = False
    if behavior_data and (behavior_data.get("is_attack_simulation") == True or is_attack_detected(behavior_data)):
        is_attack = True
    
    # Generate agent insights
    signal_insight, signal_score, signal_status, signal_latency = get_signal_collector_insight(behavior_data, is_attack)
    correlation_insight, correlation_score, correlation_status, correlation_latency = get_correlation_insight(behavior_data, trust_score, is_attack)
    behavior_insight, behavior_score, behavior_status, behavior_latency = get_behavior_trail_insight(is_attack)
    decision_insight, decision_score, decision_status, decision_latency = get_decision_insight(decision, trust_score, is_attack)
    
    # For async explainer, we'll use a simplified version in sync context
    if is_attack:
        explainer_insight = "Customer: Your account has been frozen due to suspicious automated activity. | Technical: Automated bot behavior / rapid credential injection detected. Account frozen immediately."
        explainer_score = 15
        explainer_status = "alert"
    elif decision == "grant":
        explainer_insight = "Customer: Your login looks normal and has been approved. | Technical: Normal behavioral biometrics detected."
        explainer_score = 100
        explainer_status = "done"
    elif decision == "verify":
        explainer_insight = "Customer: We need to verify your identity with a one-time code. | Technical: Moderate risk detected, step-up authentication required."
        explainer_score = 100
        explainer_status = "verify"
    else:
        explainer_insight = "Customer: Your account has been frozen for security. | Technical: High risk detected, account frozen."
        explainer_score = 15
        explainer_status = "alert"
    explainer_latency = random.randint(120, 250)
    
    agents = [
        {
            "name": "Signal Collector",
            "score": signal_score,
            "status": signal_status,
            "insight": signal_insight,
            "latency_ms": signal_latency
        },
        {
            "name": "Correlation Agent",
            "score": correlation_score,
            "status": correlation_status,
            "insight": correlation_insight,
            "latency_ms": correlation_latency
        },
        {
            "name": "Behavior Trail",
            "score": behavior_score,
            "status": behavior_status,
            "insight": behavior_insight,
            "latency_ms": behavior_latency
        },
        {
            "name": "Decision Agent",
            "score": decision_score,
            "status": decision_status,
            "insight": decision_insight,
            "latency_ms": decision_latency
        },
        {
            "name": "Explainer Agent",
            "score": explainer_score,
            "status": explainer_status,
            "insight": explainer_insight,
            "latency_ms": explainer_latency
        }
    ]
    
    return agents

# Endpoints
@app.post("/api/login")
async def login(request: LoginRequest):
    user = users_db.get(request.username)
    
    if not user or not verify_password(request.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if account is already frozen before processing
    if user["frozen"]:
        raise HTTPException(status_code=403, detail="Account frozen due to automated attack detection. OTP verification required.")
    
    # Calculate dynamic trust score based on behavioral biometrics
    behavior_dict = request.behavior_data.model_dump() if request.behavior_data else None
    
    # Check for automated attack detection - explicit check for is_attack_simulation
    attack_simulation = False
    if request.behavior_data and request.behavior_data.is_attack_simulation == True:
        attack_simulation = True
    
    attack_detected = is_attack_detected(behavior_dict) if behavior_dict else False
    
    # Determine decision based on trust score
    trust_score = calculate_trust_score(behavior_dict, request.cyberous_enabled)
    
    # If attack detected via simulation or behavioral patterns, freeze immediately
    if attack_simulation or attack_detected:
        user["frozen"] = True
        user["trust_score"] = 15
        add_audit_log(user["username"], "ATTACK_BLOCKED", "Automated bot behavior detected. Account frozen.", "critical")
        print(f"[AUDIT] ATTACK_BLOCKED user={user['username']} reason=rapid credential injection")
        raise HTTPException(status_code=403, detail="Account frozen due to automated attack detection. OTP verification required.")
    
    # Update user's trust score in database
    user["trust_score"] = trust_score
    
    # Freeze account if trust score is below 40
    if trust_score < 40:
        user["frozen"] = True
        add_audit_log(user["username"], "ACCOUNT_FROZEN", f"Trust score {trust_score} below threshold. Account frozen.", "warning")
        print(f"[AUDIT] ACCOUNT_FROZEN user={user['username']} trust_score={trust_score}")
        raise HTTPException(status_code=403, detail="Account frozen. OTP verification required.")
    
    # Add trust history entry and audit log for successful login
    add_trust_history(user["username"], trust_score)
    add_audit_log(user["username"], "LOGIN_SUCCESS", f"User logged in successfully. Trust score: {trust_score}", "info")
    print(f"[AUDIT] LOGIN_SUCCESS user={user['username']} trust_score={trust_score}")
    
    token = create_token(user["username"])
    
    # Determine decision for agents
    decision = "grant" if trust_score >= 70 else "verify" if trust_score >= 40 else "freeze"
    
    return {
        "token": token,
        "username": user["username"],
        "balance": user["balance"],
        "trust_score": trust_score,
        "agents": get_agents(trust_score, full_evaluation=True, behavior_data=behavior_dict, decision=decision)
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
    
    # Check if account is frozen or trust score is below 40
    if user["frozen"] or user["trust_score"] < 40:
        raise HTTPException(status_code=403, detail="Account frozen due to automated attack detection. OTP verification required.")
    
    # Evaluate transfer risk using risk engine
    risk_evaluation = evaluate_transfer_risk(request.amount, user["trust_score"], user["balance"])
    
    # Process transfer only if decision is "grant"
    if risk_evaluation["decision"] == "grant":
        user["balance"] -= request.amount
        add_trust_history(user["username"], user["trust_score"])
        add_audit_log(user["username"], "TRANSFER_GRANTED", f"Transfer of {request.amount} to {request.recipient} approved.", "info")
        print(f"[AUDIT] TRANSFER_GRANTED user={username} amount={request.amount} recipient={request.recipient}")
    elif risk_evaluation["decision"] == "verify":
        add_audit_log(user["username"], "TRANSFER_VERIFY", f"Transfer of {request.amount} requires verification.", "warning")
        print(f"[AUDIT] TRANSFER_VERIFY user={username} amount={request.amount}")
    elif risk_evaluation["decision"] == "freeze":
        user["frozen"] = True
        add_audit_log(user["username"], "TRANSFER_FROZEN", f"Transfer of {request.amount} blocked due to high risk. Account frozen.", "critical")
        print(f"[AUDIT] TRANSFER_FROZEN user={username} amount={request.amount}")
    
    return {
        "decision": risk_evaluation["decision"],
        "explanation": risk_evaluation["explanation"],
        "new_balance": user["balance"],
        "agents": get_agents(user["trust_score"], full_evaluation=True, behavior_data=None, decision=risk_evaluation["decision"])
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
    
    add_audit_log(user["username"], "OTP_VERIFY_SUCCESS", "Account unfrozen via OTP verification.", "info")
    
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
    # Return per-user trust history
    user_history = trust_history_db.get(username, [])
    return {"history": user_history}

@app.get("/api/audit-logs")
async def get_audit_logs(username: str = Depends(verify_token)):
    # Return latest 20 logs, newest first
    return {"logs": audit_logs_db[:20]}

@app.post("/api/reset")
async def reset_demo():
    """Reset demo database to initial state"""
    users_db["naren"]["balance"] = 12450.00
    users_db["naren"]["trust_score"] = 82
    users_db["naren"]["frozen"] = False
    
    users_db["salman"]["balance"] = 0.00
    users_db["salman"]["trust_score"] = 23
    users_db["salman"]["frozen"] = False
    
    # Clear audit logs
    global audit_logs_db, audit_log_id_counter
    audit_logs_db.clear()
    audit_log_id_counter = 0
    
    # Re-seed trust history baselines
    trust_history_db["naren"] = [
        {"login_time": "Mon 9:00 AM", "score": 85},
        {"login_time": "Tue 8:45 AM", "score": 82},
        {"login_time": "Wed 9:10 AM", "score": 88},
        {"login_time": "Thu 2:30 AM", "score": 23},
        {"login_time": "Now", "score": 82}
    ]
    trust_history_db["salman"] = [
        {"login_time": "Mon 10:00 AM", "score": 23},
        {"login_time": "Tue 11:30 AM", "score": 25},
        {"login_time": "Now", "score": 23}
    ]
    
    add_audit_log("system", "DEMO_RESET", "Demo state reset to initial values.", "info")
    
    return {"success": True, "message": "Demo state reset successfully"}

@app.get("/health")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
