from django.urls import path
from .views import menu_view, send_menu

urlpatterns = [
    path("menu", menu_view, name = 'menu'),
    path("send", send_menu , name = 'send'),
]
