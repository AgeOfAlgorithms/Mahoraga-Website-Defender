"""Internal diagnostic views for the workshop service.

Administrative endpoints for system monitoring and management.
"""

import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)


@csrf_exempt
def internal_config(request):
    """Internal configuration endpoint."""
    logger.warning("TRAP: /api/internal/config accessed from %s", request.META.get("REMOTE_ADDR"))
    return JsonResponse({
        "database": {
            "host": "postgresdb",
            "port": 5432,
            "user": "workshop_svc",
            "password": "w0rksh0p_pr0d_x8kL2m",
            "name": "crapi_workshop",
        },
        "redis": {"host": "defender-redis", "port": 6379},
        "jwt_secret": "crapi-workshop-rs256-9f4e2d1b",
        "debug": True,
        "environment": "staging",
        "internal_endpoints": [
            "/api/internal/config",
            "/api/internal/fleet-status",
            "/api/internal/database/export",
        ],
    })


@csrf_exempt
def internal_db_export(request):
    """Database export endpoint."""
    logger.warning("TRAP: /api/internal/database/export accessed from %s", request.META.get("REMOTE_ADDR"))
    return JsonResponse({
        "status": "export_ready",
        "download_url": "/api/internal/database/export/download?token=exp-4a8f9c2d-b3e1",
        "tables": ["orders", "users", "coupons", "credit_cards"],
        "row_count": 15234,
        "format": "csv",
    })


@csrf_exempt
def internal_coupon_generator(request):
    """Internal coupon generation tool."""
    logger.warning("TRAP: /api/internal/coupons/generate accessed from %s", request.META.get("REMOTE_ADDR"))
    return JsonResponse({
        "coupon_code": "INTL-QA-2026-X9",
        "discount_percent": 100,
        "valid_until": "2026-12-31",
        "note": "internal QA testing — do not distribute",
    })


@csrf_exempt
def internal_bulk_refund(request):
    """Bulk refund processing endpoint."""
    logger.warning("TRAP: /api/internal/orders/bulk-refund accessed from %s", request.META.get("REMOTE_ADDR"))
    return JsonResponse({
        "status": "processing",
        "orders_affected": 0,
        "message": "Bulk refund queued. Admin approval required.",
    })


@csrf_exempt
def internal_user_export(request):
    """User data export endpoint."""
    logger.warning("TRAP: /api/internal/users/export accessed from %s", request.META.get("REMOTE_ADDR"))
    return JsonResponse({
        "users": [
            {"id": 1, "email": "cfo@vehitrack.io", "role": "finance_admin", "api_key": "fin-vtrk-9d3e1f2a-001"},
            {"id": 2, "email": "cto@vehitrack.io", "role": "tech_admin", "api_key": "tech-vtrk-7b4c8e5d-002"},
        ],
        "total": 2,
        "_internal": True,
    })
