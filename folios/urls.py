from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Dashboards por perfil
    path('dashboard/admin/', views.dashboard_admin, name='dashboard_admin'),
    path('dashboard/subadmin/', views.dashboard_subadmin, name='dashboard_subadmin'),
    path('dashboard/jefe/', views.dashboard_jefe, name='dashboard_jefe'),
    path('dashboard/operativo/', views.dashboard_operativo, name='dashboard_operativo'),
    
    # Usuario
    path('usuarios/registro/', views.registrar_usuario, name='registrar_usuario'),
    path('usuarios/', views.usuarios_lista, name='usuarios_lista'),
    path('usuarios/<int:pk>/actualizar/', views.usuario_actualizar, name='usuario_actualizar'),
    path('usuarios/<int:pk>/toggle-activo/', views.usuario_toggle_activo, name='usuario_toggle_activo'),
    path('usuarios/<int:pk>/eliminar/', views.usuario_eliminar, name='usuario_eliminar'),

    # Registro del folio
    path('folios/registro/', views.folio_registro, name='folio_registro'),
    path('folios/consulta/', views.folios_consulta, name='folios_consulta'),
    path('folios/exportar/', views.folios_exportar_excel, name='folios_exportar_excel'),

    # Temas
    path('temas/', views.temas_lista, name='temas_lista'),
    path('temas/crear/', views.tema_crear, name='tema_crear'),
    path('temas/<int:pk>/actualizar/', views.tema_actualizar, name='tema_actualizar'),
    path('temas/<int:pk>/eliminar/', views.tema_eliminar, name='tema_eliminar'),

    # Consultar folios
    path('folios/<int:pk>/despachar/', views.folio_despachar, name='folio_despachar'),

    # Edición
    path('folios/<int:pk>/editar/', views.folio_editar, name='folio_editar'),







]
