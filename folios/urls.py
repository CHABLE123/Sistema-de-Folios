from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),

    # Dashboards por perfil
    path('dashboard/admin/', views.dashboard_admin, name='dashboard_admin'),
    path('dashboard/subadmin/', views.dashboard_subadmin, name='dashboard_subadmin'),
    path('dashboard/jefe/', views.dashboard_jefe, name='dashboard_jefe'),
    path('dashboard/operativo/', views.dashboard_operativo, name='dashboard_operativo'),
]
