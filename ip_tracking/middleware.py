from .models import RequestLog, BlockedIP
from django.http import HttpResponseForbidden
from django.core.cache import cache
import requests

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path

        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Forbidden")

        # Geolocation logic
        cache_key = f"ip_geo_{ip_address}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            try:
                # Using ip-api.com as it's a common free API for such tasks
                response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    # ip-api returns 'fail' status for private IPs sometimes, but keys might be missing
                    geo_data = {
                        'country': data.get('country'),
                        'city': data.get('city')
                    }
                    # Cache for 24 hours (86400 seconds)
                    cache.set(cache_key, geo_data, 86400)
            except Exception:
                geo_data = {}

        if not geo_data:
            geo_data = {}

        # Log the request
        RequestLog.objects.create(
            ip_address=ip_address,
            path=path,
            country=geo_data.get('country'),
            city=geo_data.get('city')
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
