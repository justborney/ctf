import json
from datetime import datetime, timezone
from pathlib import Path

import requests

from celery_app import celery_app
from price_statistics import calculate_market_stats
from settings import DATA_DIR, SOURCES_FILE


def fetch_and_build_source_stats(source_name: str, source_url: str) -> dict:
    response = requests.get(source_url, timeout=30)
    if response.status_code != 200:
        raise Exception(f"Failed to get data from source: {response.status_code}")
    data = response.json()
    if "data" in data and isinstance(data["data"], list):
        prices = data["data"]
    elif isinstance(data, list):
        prices = data
    else:
        raise Exception("Invalid data format from source")
    if len(prices) < 2:
        raise Exception("Insufficient price data from source")
    market_stats = calculate_market_stats(prices)
    source_stats = {
        "source_name": source_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stats": market_stats,
        "data_count": len(prices),
        "prices": [{"timestamp": p["timestamp"], "price": p["price"]} for p in prices]
    }
    return source_stats


@celery_app.task
def parse_all_sources():
    try:
        sources_file = Path(SOURCES_FILE)
        if not sources_file.exists():
            return {"status": "error", "error": "Sources file not found"}
        with open(sources_file, "r") as f:
            data = json.load(f)
        sources = data.get("sources", [])
        for source in sources:
            parse_source.delay(source["name"], source["url"])
        return {
            "status": "success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources_scheduled": len(sources)
        }
    except Exception as e:
        print(f"Error in parse_all_sources: {str(e)}")
        return {"status": "error", "error": str(e)}

@celery_app.task
def parse_source(source_name: str, source_url: str):
    try:
        source_stats = fetch_and_build_source_stats(source_name, source_url)
        save_source_stats(source_name, source_stats)
        return {
            "status": "success",
            "source": source_name,
            "timestamp": source_stats["timestamp"],
            "data_count": source_stats["data_count"]
        }
    except Exception as e:
        print(f"Error parsing source {source_name}: {str(e)}")
        return {"status": "error", "source": source_name, "error": str(e)}


def save_source_stats(source_name: str, source_stats: dict):
    data_dir = Path(DATA_DIR)
    data_dir.mkdir(exist_ok=True)
    stats_file = data_dir / f"source_stats_{source_name}.json"
    with open(stats_file, "w") as f:
        json.dump(source_stats, f, indent=2, default=str)
