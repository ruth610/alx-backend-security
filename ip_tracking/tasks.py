from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP
from django.db.models import Count

@shared_task
def flag_suspicious_ips():
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # 1. IPs exceeding 100 requests/hour
    requests_last_hour = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
    ip_counts = requests_last_hour.values('ip_address').annotate(count=Count('ip_address'))

    for entry in ip_counts:
        if entry['count'] > 100:
            ip = entry['ip_address']
            if not SuspiciousIP.objects.filter(ip_address=ip, reason="High request volume").exists():
                SuspiciousIP.objects.create(ip_address=ip, reason="High request volume")

    # 2. Accessing sensitive paths
    # Paths like /admin, /login
    sensitive_prefixes = ['/admin', '/login']

    for prefix in sensitive_prefixes:
        # Filter usage of sensitive paths
        sensitive_requests = requests_last_hour.filter(path__startswith=prefix).values('ip_address').distinct()

        for entry in sensitive_requests:
            ip = entry['ip_address']
            reason = f"Accessed sensitive path: {prefix}"
            if not SuspiciousIP.objects.filter(ip_address=ip, reason__startswith="Accessed sensitive path").exists():
                SuspiciousIP.objects.create(ip_address=ip, reason=reason)
