from pydantic import BaseModel, Field
from typing import List, Annotated


class PriceData(BaseModel):
    timestamp: str
    price: float

class MarketStats(BaseModel):
    volatility: float
    rsi: float
    support_level: float
    resistance_level: float
    trend: str
    sentiment_score: float

class Source(BaseModel):
    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")]
    url: str

class SourceList(BaseModel):
    sources: List[Source]

class SourceStats(BaseModel):
    source_name: str
    timestamp: str
    stats: MarketStats
    data_count: int
    prices: List[PriceData]
