
from django.contrib import admin
from django.urls import path, include

from dig_the_data import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('quiz_app.urls')),
]