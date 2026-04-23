from django.urls import path
from . import views

urlpatterns = [
    path("config", views.internal_config),
    path("database/export", views.internal_db_export),
    path("coupons/generate", views.internal_coupon_generator),
    path("orders/bulk-refund", views.internal_bulk_refund),
    path("users/export", views.internal_user_export),
]
