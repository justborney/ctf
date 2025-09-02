import random
import statistics
from typing import List, Dict, Any

def calculate_market_stats(prices: List[Dict[str, Any]]) -> Dict[str, Any]:
    if len(prices) < 2:
        return get_default_stats()
    
    price_values = [p["price"] for p in prices]
    current_price = price_values[-1]

    volatility = calculate_volatility(price_values)
    rsi = calculate_rsi(price_values)
    
    support_level = current_price * 0.92
    resistance_level = current_price * 1.08
    
    trend = determine_trend_simple(price_values)
    
    sentiment_score = calculate_sentiment(rsi, trend)
    
    return {
        "volatility": volatility,
        "rsi": rsi,
        "support_level": support_level,
        "resistance_level": resistance_level,
        "trend": trend,
        "sentiment_score": sentiment_score
    }

def get_default_stats() -> Dict[str, Any]:
    return {
        "volatility": 0.0,
        "rsi": 50.0,
        "support_level": 0.0,
        "resistance_level": 0.0,
        "trend": "neutral",
        "sentiment_score": 0.0
    }

def calculate_volatility(price_values: List[float]) -> float:
    if len(price_values) < 2:
        return 0.0
    
    returns = []
    for i in range(1, len(price_values)):
        if price_values[i-1] != 0:
            ret = (price_values[i] - price_values[i-1]) / price_values[i-1]
            returns.append(ret)
    
    if not returns:
        return 0.0
    
    volatility = statistics.stdev(returns) if len(returns) > 1 else 0.01
    return volatility * 100

def calculate_rsi(price_values: List[float]) -> float:
    if len(price_values) < 14:
        return 50.0
    
    gains = []
    losses = []
    
    for i in range(1, len(price_values)):
        change = price_values[i] - price_values[i-1]
        if change > 0:
            gains.append(change)
            losses.append(0.0)
        else:
            gains.append(0.0)
            losses.append(abs(change))
    
    if len(gains) < 14:
        return 50.0
    
    avg_gain = statistics.mean(gains[-14:])
    avg_loss = statistics.mean(losses[-14:])
    
    if avg_loss == 0:
        return 100.0
    
    rs = avg_gain / avg_loss
    rsi = 100 - (100 / (1 + rs))
    
    return rsi


def determine_trend_simple(price_values: List[float]) -> str:
    if len(price_values) < 5:
        return "neutral"
    
    recent_prices = price_values[-5:]
    price_change = (recent_prices[-1] - recent_prices[0]) / recent_prices[0]
    
    if price_change > 0.02:
        return "bullish"
    elif price_change < -0.02:
        return "bearish"
    else:
        return "neutral"

def calculate_sentiment(rsi: float, trend: str) -> float:
    base_sentiment = 0.0
    
    if trend == "bullish":
        base_sentiment += 0.3
    elif trend == "bearish":
        base_sentiment -= 0.3
    
    if rsi > 70:
        base_sentiment -= 0.2
    elif rsi < 30:
        base_sentiment += 0.2
    
    sentiment = base_sentiment + random.gauss(0, 0.1)
    
    if sentiment > 1:
        sentiment = 1.0
    elif sentiment < -1:
        sentiment = -1.0
    
    return sentiment
