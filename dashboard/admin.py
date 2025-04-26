from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import HttpLog, ModelConfig, AttackType, RiskLevel


@admin.register(HttpLog)
class HttpLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "ip", "method", "url", "status_code", "label", "risk_level")
    list_filter = ("label", "risk_level", "method", "status_code", "timestamp")
    search_fields = ("ip", "url", "referrer", "user_agent", "raw_log")
    ordering = ("-timestamp",)
    readonly_fields = ("timestamp", "raw_log")
    list_per_page = 25

    def has_add_permission(self, request):
        # Kullanıcı manuel HttpLog eklemesin, sadece görüntülesin
        return False


@admin.register(ModelConfig)
class ModelConfigAdmin(admin.ModelAdmin):
    list_display = ("model_name", "version", "trained_at", "enabled", "batch_size", "scan_interval_seconds")
    list_filter = ("enabled",)
    search_fields = ("model_name", "version", "description", "alert_email")
    ordering = ("-trained_at",)
    list_editable = ("enabled", "batch_size", "scan_interval_seconds")
    fieldsets = (
        (None, {
            "fields": ("model_name", "version", "trained_at", "description")
        }),
        ("Scan Settings", {
            "fields": ("scan_interval_seconds", "batch_size", "enabled")
        }),
        ("Threshold & Retention", {
            "fields": ("threshold_score", "auto_delete_old_logs", "log_retention_days")
        }),
        ("Alert Settings", {
            "fields": ("alert_email", "max_risk_level_to_alert")
        }),
    )
