from django.shortcuts import render
from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit

def rate_limit_check(group, request):
    if request.user.is_authenticated:
        return '10/m'
    return '5/m'

@ratelimit(key='ip', rate=rate_limit_check, method='ALL', block=True)
def login_view(request):
    return HttpResponse("Login Page")
