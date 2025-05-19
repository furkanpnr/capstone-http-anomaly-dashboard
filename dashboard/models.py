from django.db import models
from django.utils.translation import gettext_lazy as _


class AttackType(models.TextChoices):
    NORMAL = "normal", _("Normal")
    PATH_TRAVERSAL = "path_traversal", _("Path Traversal")
    SQLI = "sqli", _("SQL Injection")
    XSS = "xss", _("Cross-Site Scripting (XSS)")
    COMMAND_INJECTION = "command_injection", _("Command Injection")


class RiskLevel(models.TextChoices):
    NORMAL = "normal", _("Normal")
    LOW = "low", _("Low")
    MEDIUM = "medium", _("Medium")
    HIGH = "high", _("High")


class HttpLog(models.Model):
    ip = models.GenericIPAddressField()
    timestamp = models.DateTimeField()
    method = models.CharField(max_length=10)
    url = models.TextField()
    protocol = models.CharField(max_length=20)
    status_code = models.IntegerField()
    size = models.PositiveIntegerField()
    referrer = models.CharField(max_length=500, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    raw_log = models.TextField()

    # ML Prediction fields
    label = models.CharField(
        max_length=50,
        choices=AttackType.choices,
        default=AttackType.NORMAL,
    )
    risk_level = models.CharField(
        max_length=10,
        choices=RiskLevel.choices,
        default=RiskLevel.LOW,
    )

    scanned_at = models.DateTimeField(auto_now_add=True)

    def is_anomalous(self):
        return self.label != AttackType.NORMAL

    def __str__(self):
        return f"{self.ip} - {self.method} {self.url} [{self.label}]"


class ModelConfig(models.Model):
    model_name = models.CharField(max_length=255)
    version = models.CharField(max_length=50)
    trained_at = models.DateTimeField()
    description = models.TextField(blank=True)

    # New configuration fields
    scan_interval_seconds = models.PositiveIntegerField(
        default=60,
        help_text="Scan interval in seconds."
    )
    batch_size = models.PositiveIntegerField(
        default=10,
        help_text="Number of logs to scan per interval."
    )
    enabled = models.BooleanField(
        default=True,
        help_text="Enable or disable the scanning."
    )
    alert_email = models.EmailField(
        blank=True,
        help_text="Email address to send alerts to."
    )
    max_risk_level_to_alert = models.CharField(
        max_length=10,
        choices=RiskLevel.choices,
        default=RiskLevel.HIGH,
        help_text="Trigger alerts for logs with this risk level or higher."
    )

    def __str__(self):
        return f"{self.model_name} v{self.version}"
