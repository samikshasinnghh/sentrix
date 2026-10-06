from collections import defaultdict

_totals = {"requests": 0, "errors": 0}
_by_route_status = defaultdict(int)
_latency = defaultdict(lambda: {"count": 0, "total_ms": 0.0, "max_ms": 0.0})


def record_request(method: str, route: str, status: int, ms: float) -> None:
    _totals["requests"] += 1
    if status >= 500:
        _totals["errors"] += 1

    _by_route_status[f"{method} {route} {status}"] += 1

    lat = _latency[f"{method} {route}"]
    lat["count"] += 1
    lat["total_ms"] += ms
    lat["max_ms"] = max(lat["max_ms"], ms)


def snapshot() -> dict:
    return {
        "requests_total": _totals["requests"],
        "errors_total": _totals["errors"],
        "requests_by_route_status": dict(_by_route_status),
        "latency_ms": {
            key: {
                "count": v["count"],
                "avg": round(v["total_ms"] / v["count"], 1),
                "max": round(v["max_ms"], 1),
            }
            for key, v in _latency.items()
        },
    }