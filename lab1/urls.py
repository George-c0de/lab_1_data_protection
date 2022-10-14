from django.contrib import admin
from django.urls import path

from .views import *

urlpatterns = [
    path('', persona, name='persona'),
    path('admin_persona', admin_persona, name='admin_persona'),
    path('admin_home', admin_home, name='admin_home'),
    path('add_user', add_user, name='add_user'),
    path('set_user', set_user, name='set_user'),
    path('change_password', change_password, name='change_password'),
    path('lk_persona', lk_persona, name='lk_persona'),
    path('change_password_user', change_password_user, name='change_password_user'),
    path('check_user', check_user, name='check_user'),
    path('about', about, name='about')
]
