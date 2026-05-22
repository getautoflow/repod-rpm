"""
routers/metrics_router.py — [T] Endpoint GET /metrics (format Prometheus)

Exposé SANS préfixe /api/v1 (endpoint infra, comme GET /health).
Aucune authentification : le scrape Prometheus est interne (isolation réseau).

Content-Type : text/plain; version=0.0.4; charset=utf-8 (CONTENT_TYPE_LATEST)
"""

from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from services.metrics import REGISTRY

router = APIRouter(tags=["Metrics"])


@router.get("/metrics", include_in_schema=False)
def get_metrics() -> Response:
    """
    Retourne les métriques Prometheus au format text/plain (exposition standard).
    Scraped par Prometheus server ou compatible (VictoriaMetrics, Grafana Agent…).
    """
    data = generate_latest(REGISTRY)
    return Response(
        content=data,
        media_type=CONTENT_TYPE_LATEST,
    )
