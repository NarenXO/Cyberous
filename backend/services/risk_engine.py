from typing import Optional, Dict

# Normal baseline values for behavioral biometrics
BASELINE = {
    "avg_keystroke_interval": (100, 150),  # ms
    "avg_hold_duration": (70, 100),  # ms
    "avg_mouse_velocity": (1.5, 3.5)  # pixels/ms
}

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
    
    try:
        # Extract metrics from behavior_data
        keystroke_interval = behavior_data.get("avg_keystroke_interval", 125)
        hold_duration = behavior_data.get("avg_hold_duration", 85)
        mouse_velocity = behavior_data.get("avg_mouse_velocity", 2.5)
        
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
        
        # Round to integer
        return int(trust_score)
        
    except (KeyError, TypeError, ValueError):
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

def evaluate_transfer_risk(amount: float, trust_score: int, balance: float) -> Dict:
    """
    Evaluate transaction risk and determine decision.
    
    Args:
        amount: Transfer amount
        trust_score: User's current trust score
        balance: User's current balance
    
    Returns:
        Dict with decision, explanation, and agent scores
    """
    if trust_score >= 70 and amount <= balance:
        return {
            "decision": "grant",
            "explanation": "Transaction approved based on risk evaluation.",
            "signal_collector_score": 100,
            "correlation_score": trust_score,
            "behavior_trail_score": 15,
            "decision_score": 20,
            "explainer_score": 100
        }
    elif 40 <= trust_score < 70:
        return {
            "decision": "verify",
            "explanation": "Step-up authentication required due to moderate risk.",
            "signal_collector_score": 100,
            "correlation_score": trust_score,
            "behavior_trail_score": 45,
            "decision_score": 50,
            "explainer_score": 100
        }
    else:
        return {
            "decision": "freeze",
            "explanation": "High behavioral anomaly detected. Account frozen.",
            "signal_collector_score": 100,
            "correlation_score": trust_score,
            "behavior_trail_score": 85,
            "decision_score": 90,
            "explainer_score": 100
        }
