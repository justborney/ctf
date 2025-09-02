import json
import re
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web

from settings import DATA_DIR, UPLOADS_DIR, RESULTS_DIR, SOURCES_FILE, PEACH_COIN_SERVICE_URL, APP_TITLE
from price_statistics import calculate_market_stats
from tasks import fetch_and_build_source_stats, save_source_stats

routes = web.RouteTableDef()


@routes.get("/")
async def index(request: web.Request) -> web.StreamResponse:
    static_dir = Path(__file__).resolve().parent / "static"
    index_path = static_dir / "index.html"
    if not index_path.exists():
        return web.Response(text=f"{APP_TITLE}", content_type="text/html")
    return web.FileResponse(path=index_path)


@routes.post("/upload")
async def upload_file(request: web.Request) -> web.Response:
    try:
        upload_dir = Path(UPLOADS_DIR)
        upload_dir.mkdir(exist_ok=True)

        reader = await request.multipart()
        part = await reader.next()
        if part is None or part.name != "file":
            return web.json_response({"detail": "No file part provided"}, status=400)

        source = request.rel_url.query.get("source", "")
        if not source:
            return web.json_response({"detail": "Missing source parameter"}, status=400)
        filename = part.filename
        if not filename:
            return web.json_response({"detail": "No filename provided"}, status=400)

        base_dir = Path(UPLOADS_DIR) / source
        file_path = base_dir / Path(filename)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "wb") as f:
            while True:
                chunk = await part.read_chunk()
                if not chunk:
                    break
                f.write(chunk)

        text = file_path.read_text(encoding="utf-8")
        payload = json.loads(text)
        if isinstance(payload, dict) and "prices" in payload:
            prices = payload["prices"]
        elif isinstance(payload, list):
            prices = payload
        else:
            prices = []
        if not isinstance(prices, list):
            prices = []
        stats = {
            "source_name": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stats": calculate_market_stats(prices),
            "data_count": len(prices),
            "prices": prices,
        }

        results_dir = Path(RESULTS_DIR) / source
        results_dir.mkdir(parents=True, exist_ok=True)
        results_path = results_dir / Path(filename)
        results_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")

        return web.json_response({
            "message": "File uploaded successfully",
            "filename": filename,
            "source": source,
            "result_path": str(results_path)
        })
    except Exception as e:
        return web.json_response({"detail": f"Upload failed: {str(e)}"}, status=500)


@routes.get("/download/{file_path}")
async def download_file(request: web.Request) -> web.StreamResponse:
    try:
        source = request.rel_url.query.get("source", "")
        if not source:
            return web.json_response({"detail": "Missing source parameter"}, status=400)
        file_path = request.match_info["file_path"]
        base_dir = Path(RESULTS_DIR) / source
        full_path = base_dir / file_path
        if not full_path.exists():
            return web.json_response({"detail": "File not found"}, status=404)
        return web.FileResponse(path=full_path)
    except Exception as e:
        return web.json_response({"detail": f"Download failed: {str(e)}"}, status=500)


@routes.get("/sources")
async def get_sources(request: web.Request) -> web.Response:
    try:
        sources_file = Path(SOURCES_FILE)
        if not sources_file.exists():
            return web.json_response({"sources": []})
        with open(sources_file, "r") as f:
            data = json.load(f)
        return web.json_response(data)
    except Exception as e:
        return web.json_response({"detail": f"Error reading sources: {str(e)}"}, status=500)


@routes.post("/sources")
async def add_source(request: web.Request) -> web.Response:
    try:
        body = await request.json()
        name = body.get("name", "")
        url = body.get("url", "")
        if not isinstance(name, str) or not re.match(r"^[A-Za-z0-9_-]+$", name):
            return web.json_response({"detail": "Invalid source name"}, status=400)
        if not isinstance(url, str) or not url:
            return web.json_response({"detail": "Invalid url"}, status=400)

        sources_file = Path(SOURCES_FILE)
        sources_file.parent.mkdir(exist_ok=True)
        sources = []
        if sources_file.exists():
            with open(sources_file, "r") as f:
                data = json.load(f)
                sources = data.get("sources", [])
        if any(s.get("name") == name for s in sources):
            return web.json_response({"detail": "Source with this name already exists"}, status=400)
        sources.append({"name": name, "url": url})
        with open(sources_file, "w") as f:
            json.dump({"sources": sources}, f, indent=2)
        return web.json_response({"name": name, "url": url})
    except Exception as e:
        return web.json_response({"detail": f"Error adding source: {str(e)}"}, status=500)


@routes.get("/sources/{source_name}/stats")
async def get_source_stats(request: web.Request) -> web.Response:
    try:
        source_name = request.match_info["source_name"]
        stats_file = Path(f"{DATA_DIR}/source_stats_{source_name}.json")
        if not stats_file.exists():
            return web.json_response({"detail": "Source statistics not found"}, status=404)
        with open(stats_file, "r") as f:
            data = json.load(f)
        return web.json_response(data)
    except Exception as e:
        return web.json_response({"detail": f"Error reading source statistics: {str(e)}"}, status=500)


def initialize_sources_file() -> None:
    sources_file = Path(SOURCES_FILE)
    sources_file.parent.mkdir(exist_ok=True)
    if not sources_file.exists():
        default_sources = {
            "sources": [
                {"name": "peach-coin", "url": f"{PEACH_COIN_SERVICE_URL}/prices"}
            ]
        }
        with open(sources_file, "w") as f:
            json.dump(default_sources, f, indent=2)
        print("Sources file initialized with default peach-coin source")


def initialize_missing_source_stats() -> None:
    try:
        sources_file = Path(SOURCES_FILE)
        if not sources_file.exists():
            return
        with open(sources_file, "r") as f:
            data = json.load(f)
        sources = data.get("sources", [])
        for s in sources:
            try:
                stats_path = Path(f"{DATA_DIR}/source_stats_{s['name']}.json")
                if stats_path.exists():
                    continue
                source_stats = fetch_and_build_source_stats(s["name"], s["url"])
                save_source_stats(s["name"], source_stats)
            except Exception:
                continue
    except Exception:
        pass


@routes.get("/results")
async def list_results(request: web.Request) -> web.Response:
    try:
        results_root = Path(RESULTS_DIR)
        if not results_root.exists():
            return web.json_response({})
        result: dict[str, list] = {}
        for source_dir in results_root.iterdir():
            if not source_dir.is_dir():
                continue
            bucket = []
            for file in sorted(source_dir.glob("**/*")):
                if file.is_file():
                    try:
                        bucket.append(file.name)
                    except Exception:
                        continue
            result[source_dir.name] = bucket
        return web.json_response(result)
    except Exception as e:
        return web.json_response({"detail": f"Error reading results: {str(e)}"}, status=500)


async def on_startup(app: web.Application) -> None:
    initialize_sources_file()
    initialize_missing_source_stats()


def create_app() -> web.Application:
    app = web.Application()
    app.add_routes(routes)
    static_dir = Path(__file__).resolve().parent / "static"
    app.router.add_static("/static/", path=static_dir, name="static")
    app.on_startup.append(on_startup)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=8000)
