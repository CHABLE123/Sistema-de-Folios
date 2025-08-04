from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import Usuario, Folio, Tema

class UsuarioAdmin(BaseUserAdmin):
    list_display = ('numero_empleado', 'nombre', 'email', 'perfil', 'is_staff')
    search_fields = ('numero_empleado', 'nombre', 'email')
    list_filter = ('perfil',)
    ordering = ('numero_empleado',)

    fieldsets = (
        (None, {'fields': ('numero_empleado', 'password')}),
        ('Información personal', {'fields': ('nombre', 'apellido_paterno', 'apellido_materno', 'rfc', 'email')}),
        ('Permisos', {'fields': ('perfil', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('numero_empleado', 'email', 'password1', 'password2', 'perfil'),
        }),
    )

admin.site.register(Usuario, UsuarioAdmin)
admin.site.register(Folio)
admin.site.register(Tema)
