from typing import Optional, Dict
import os
import httpx
import asyncio

# Normal baseline values for behavioral biometrics
BASELINE = {
    "avg_keystroke_interval": (100, 150),  # ms
    "avg_hold_duration": (70, 100),  # ms
    "avg_mouse_velocity": (1.5, 3.5)  # pixels/ms
}

def is_attack_detected(behavior_data: Optional[Dict]) -> bool:
    """
    Detect automated bot/rapid attack patterns in behavior data.
    
    Args:
        behavior_data: Dict containing behavioral metrics (can be None or partial)
    
    Returns:
        True if attack patterns are detected, False otherwise
    """
    # Handle None or empty behavior_data
    if not behavior_data or not isinstance(behavior_data, dict):
        return False
    
    # Check for explicit attack simulation flag
    if behavior_data.get("is_attack_simulation") == True:
        return True
    
    # Check for bot-like keystroke patterns (too fast)
    keystroke_interval = behavior_data.get("avg_keystroke_interval", 125)
    if keystroke_interval is not None and keystroke_interval < 30:
        return True
    
    # Check for bot-like hold duration (too short)
    hold_duration = behavior_data.get("avg_hold_duration", 85)
    if hold_duration is not None and hold_duration < 20:
        return True
    
    # Check for rapid session duration (too short)
    session_duration = behavior_data.get("session_duration", 1000)
    if session_duration is not None and session_duration < 500:
        return True
    
    return False

def calculate_trust_score(behavior_data: Optional[Dict], cyberous_enabled: bool) -> int:
    """
    Calculate trust score (0-100) based on behavioral biometrics data.
    
    Args:
        behavior_data: Dict containing keystroke and mouse metrics
        cyberous_enabled: Whether behavioral biometrics is enabled
    
    Returns:
        Trust score between 0-100
    """
    # Default trust score if behavioral biometrics is disabled or no data
    if not cyberous_enabled or behavior_data is None:
        return 50
    
    # Check for automated bot/rapid attack patterns
    if is_attack_detected(behavior_data):
        return 15  # Force low trust score for attacks
    
    try:
        # Extract metrics from behavior_data with safe defaults
        keystroke_interval = behavior_data.get("avg_keystroke_interval", 125) if behavior_data else 125
        hold_duration = behavior_data.get("avg_hold_duration", 85) if behavior_data else 85
        mouse_velocity = behavior_data.get("avg_mouse_velocity", 2.5) if behavior_data else 2.5
        location = behavior_data.get("location", "Local Baseline") if behavior_data else "Local Baseline"
        
        # Ensure values are numeric before calculation
        keystroke_interval = float(keystroke_interval) if keystroke_interval is not None else 125
        hold_duration = float(hold_duration) if hold_duration is not None else 85
        mouse_velocity = float(mouse_velocity) if mouse_velocity is not None else 2.5
        
        # Calculate deviation from baseline for each metric
        keystroke_deviation = calculate_deviation(
            keystroke_interval, 
            BASELINE["avg_keystroke_interval"][0], 
            BASELINE["avg_keystroke_interval"][1]
        )
        
        hold_deviation = calculate_deviation(
            hold_duration,
            BASELINE["avg_hold_duration"][0],
            BASELINE["avg_hold_duration"][1]
        )
        
        mouse_deviation = calculate_deviation(
            mouse_velocity,
            BASELINE["avg_mouse_velocity"][0],
            BASELINE["avg_mouse_velocity"][1]
        )
        
        # Average deviation score (0-100, where 0 is perfect match, 100 is extreme deviation)
        avg_deviation = (keystroke_deviation + hold_deviation + mouse_deviation) / 3
        
        # Convert deviation to trust score (higher deviation = lower trust)
        trust_score = max(0, min(100, 100 - avg_deviation))
        
        # Deduct 15 points if location is outside baseline (untrusted)
        if location not in ["Local Baseline", "Home", "Office", "Known Location"]:
            trust_score = max(0, trust_score - 15)
        
        # Round to integer
        return int(trust_score)
        
    except (KeyError, TypeError, ValueError, AttributeError):
        # If data is malformed, return moderate trust score
        return 50

def calculate_deviation(value: float, min_baseline: float, max_baseline: float) -> float:
    """
    Calculate deviation score from baseline range.
    
    Args:
        value: Measured value
        min_baseline: Minimum expected baseline
        max_baseline: Maximum expected baseline
    
    Returns:
        Deviation score (0-100)
    """
    if min_baseline <= value <= max_baseline:
        # Within normal range - low deviation
        center = (min_baseline + max_baseline) / 2
        range_width = max_baseline - min_baseline
        deviation_from_center = abs(value - center)
        # Normalize to 0-20 range for values within baseline
        return (deviation_from_center / range_width) * 20
    else:
        # Outside normal range - calculate how far outside
        if value < min_baseline:
            deviation = (min_baseline - value) / min_baseline
        else:
            deviation = (value - max_baseline) / max_baseline
        
        # Scale to 20-100 range
        return min(100, 20 + deviation * 80)

async def get_grok_explanation(decision: str, trust_score: int) -> str:
    """
    Get explanation from Grok API for the decision.
    
    Args:
        decision: The decision made (grant, verify, freeze)
        trust_score: The trust score
    
    Returns:
        Explanation string from Grok or fallback
    """
    grok_api_key = os.getenv("GROK_API_KEY")
    
    if not grok_api_key:
        return get_fallback_explanation(decision, trust_score)
    
    try:
        print("[GROK AI] Contacting xAI Grok-2 API...")
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.post(
                "https://api.x.ai/v1/chat/completions",
                headers={
                    "Authorization": "Bearer " + grok_api_key,
                    "Content-Type": "application/json"
                },
                json={
                    "model": "grok-2-latest",
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are the Cyberous Explainer Agent. Explain banking fraud decisions in 1 short sentence."
                        },
                        {
                            "role": "user",
                            "content": f"Decision: {decision}, Trust Score: {trust_score}. Explain this decision."
                        }
                    ],
                    "max_tokens": 50
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                explanation = data["choices"][0]["message"]["content"].strip()
                print(f"[GROK AI RESPONSE]: {explanation}")
                return explanation
            else:
                return get_fallback_explanation(decision, trust_score)
    except (httpx.TimeoutException, httpx.HTTPError, KeyError, IndexError):
        return get_fallback_explanation(decision, trust_score)

def get_fallback_explanation(decision: str, trust_score: int, is_attack: bool = False) -> str:
    """
    Get fallback explanation when Grok API is unavailable.
    
    Args:
        decision: The decision made
        trust_score: The trust score
        is_attack: Whether this is an attack detection
    
    Returns:
        Fallback explanation string
    """
    if is_attack:
        return "Critical Threat: Automated bot behavior / rapid credential injection detected. Account frozen immediately."
    elif decision == "grant":
        return "Transaction approved: Normal behavioral biometrics detected."
    elif decision == "verify":
        return "Step-up authentication required: Moderate risk detected."
    elif decision == "freeze":
        return "Account frozen: High behavioral anomaly detected."
    else:
        return "Transaction reviewed based on risk evaluation."

def evaluate_transfer_risk(amount: float, trust_score: int, balance: float, is_attack: bool = False) -> Dict:
    """
    Evaluate transaction risk and determine decision.
    
    Args:
        amount: Transfer amount
        trust_score: User's current trust score
        balance: User's current balance
        is_attack: Whether this is an attack detection
    
    Returns:
        Dict with decision, explanation, and agent scores
    """
    if is_attack:
        decision = "freeze"
        explanation = get_fallback_explanation(decision, trust_score, is_attack=True)
        return {
            "decision": decision,
            "explanation": explanation,
            "signal_collector_score": 100,
            "correlation_score": trust_score,
            "behavior_trail_score": 100,
            "decision_score": 100,
            "explainer_score": 100
        }
    elif trust_score >= 70 and amount <= balance:
        decision = "grant"
        explanation = get_fallback_explanation(decision, trust_score)
        return {
            "decision": decision,
            "explanation": explanation,
            "signal_collector_score": 100,
            "correlation_score": trust_score,
            "behavior_trail_score": 15,
            "decision_score": 20,
            "explainer_score": 100
        }
    elif 40 <= trust_score < 70:
        decision = "verify"
        explanation = get_fallback_explanation(decision, trust_score)
        return {
            "decision": decision,
            "explanation": explanation,
            "signal_collector_score": 100,
            "correlation_score": trust_score,
            "behavior_trail_score": 45,
            "decision_score": 50,
            "explainer_score": 100
        }
    else:
        decision = "freeze"
        explanation = get_fallback_explanation(decision, trust_score)
        return {
            "decision": decision,
            "explanation": explanation,
            "signal_collector_score": 100,
            "correlation_score": trust_score,
            "behavior_trail_score": 85,
            "decision_score": 90,
            "explainer_score": 100
        }
