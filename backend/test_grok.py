import asyncio
import os
from dotenv import load_dotenv
from services.risk_engine import get_grok_explanation

# Load environment variables
load_dotenv()

async def test_grok_api():
    """Test the Grok API with a live call"""
    print("Testing Grok API connection...")
    print(f"GROK_API_KEY set: {bool(os.getenv('GROK_API_KEY'))}")
    
    # Test with a sample decision
    decision = "grant"
    trust_score = 85
    
    explanation = await get_grok_explanation(decision, trust_score)
    
    print(f"\nDecision: {decision}")
    print(f"Trust Score: {trust_score}")
    print(f"Explanation: {explanation}")
    
    return explanation

if __name__ == "__main__":
    asyncio.run(test_grok_api())
