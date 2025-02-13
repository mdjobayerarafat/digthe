from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from datetime import timedelta

class SessionCleanupMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Clean up sessions older than a certain period (e.g., 1 day)
        ActiveSession.objects.filter(created_at__lt=timezone.now() - timedelta(days=1)).delete()