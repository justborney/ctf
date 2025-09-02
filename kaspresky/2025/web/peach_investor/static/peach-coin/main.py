from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import json
import random
import math
from datetime import datetime, timedelta
from pathlib import Path
from pydantic import BaseModel
from typing import List

app = FastAPI(title="Peach Coin Price Service")

class PriceData(BaseModel):
    timestamp: str
    price: float

class PriceResponse(BaseModel):
    data: List[PriceData]
    count: int

@app.on_event("startup")
async def startup_event():
    initialize_price_data()

@app.get("/")
async def root():
    return {"message": "Peach Coin Price Service"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/prices", response_model=PriceResponse)
async def get_prices():
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    data_file = data_dir / Path("price_data.json")
    
    if not data_file.exists():
        raise HTTPException(status_code=404, detail="No price data available yet")
    
    try:
        update_price_data_if_needed()
        
        with open(data_file, "r") as f:
            data = json.load(f)
        
        price_data_list = [PriceData(**item) for item in data]
        return PriceResponse(data=price_data_list, count=len(price_data_list))
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading price data: {str(e)}")

def initialize_price_data():
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    data_file = data_dir / "price_data.json"
    
    if not data_file.exists():
        existing_data = []
    else:
        try:
            with open(data_file, "r") as f:
                existing_data = json.load(f)
        except:
            existing_data = []
    
    if len(existing_data) < 100:
        print(f"Initializing price data with {100 - len(existing_data)} new records...")
        
        current_time = datetime.utcnow()
        base_price = 45000.0
        
        for i in range(100 - len(existing_data)):
            timestamp = current_time - timedelta(minutes=100-i-1)
            price = generate_realistic_price(base_price, i)
            
            price_data = {
                "timestamp": timestamp.isoformat(),
                "price": price
            }
            existing_data.append(price_data)
        
        with open(data_file, "w") as f:
            json.dump(existing_data, f, indent=2)
        
        print(f"Price data initialized with {len(existing_data)} records")

def update_price_data_if_needed():
    data_dir = Path("data")
    data_file = data_dir / "price_data.json"
    
    if not data_file.exists():
        initialize_price_data()
        return
    
    try:
        with open(data_file, "r") as f:
            data = json.load(f)
    except:
        data = []
    
    if not data:
        initialize_price_data()
        return
    
    last_record = data[-1]
    last_timestamp = datetime.fromisoformat(last_record["timestamp"])
    current_time = datetime.utcnow()
    
    if (current_time - last_timestamp).total_seconds() >= 60:
        last_price = last_record["price"]
        new_price = generate_realistic_price(last_price, 0)
        
        new_record = {
            "timestamp": current_time.isoformat(),
            "price": new_price
        }
        
        if len(data) >= 100:
            data.pop(0)
        
        data.append(new_record)
        
        with open(data_file, "w") as f:
            json.dump(data, f, indent=2)
        
        print(f"Price updated at {current_time.isoformat()}: {new_price}")

def generate_realistic_price(base_price: float, index: int):
    if index == 0:
        return base_price
    
    volatility = 0.02
    trend_factor = 0.001 * math.sin(index * 0.1)
    random_factor = random.gauss(0, volatility)
    
    price_change = base_price * (trend_factor + random_factor)
    new_price = base_price + price_change
    
    if new_price < 1000:
        new_price = 1000
    elif new_price > 100000:
        new_price = 100000
    
    return round(new_price, 2)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
