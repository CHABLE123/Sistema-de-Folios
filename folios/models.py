from django.db import models, transaction
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
from datetime import timedelta

class Tema(models.Model):
    nombre = models.CharField(max_length=150, unique=True)
    activo = models.BooleanField(default=True)
    creado_en = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['nombre']

    def __str__(self):
        return self.nombre

PERFILES = (
    ('ADMIN', 'Administrador'),
    ('SUBADMIN', 'Subadministrador'),
    ('JEFE', 'Jefe de Departamento'),
    ('OPERATIVO', 'Operativo'),
)

class UsuarioManager(BaseUserManager):
    def create_user(self, numero_empleado, email, password=None, **extra_fields):
        if not numero_empleado:
            raise ValueError('El número de empleado es obligatorio')
        email = self.normalize_email(email)
        user = self.model(numero_empleado=numero_empleado, email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, numero_empleado, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(numero_empleado, email, password, **extra_fields)

class Usuario(AbstractBaseUser, PermissionsMixin):
    nombre = models.CharField(max_length=100)
    apellido_paterno = models.CharField(max_length=100)
    apellido_materno = models.CharField(max_length=100)
    rfc = models.CharField(max_length=13, unique=True)
    numero_empleado = models.CharField(max_length=10, unique=True)
    email = models.EmailField(unique=True)
    perfil = models.CharField(max_length=15, choices=PERFILES)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UsuarioManager()

    USERNAME_FIELD = 'numero_empleado'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return f"{self.numero_empleado} - {self.nombre}"
    
    def nombre_completo(self):
        return f"{self.nombre} {self.apellido_paterno} {self.apellido_materno}"

class Folio(models.Model):
    TIPO_FIRMADO = (
        ('AUTOGRAFO', 'Autógrafo'),
        ('SIFEN', 'SIFEN'),
    )

    ESTATUS = (
        ('PENDIENTE', 'Pendiente'),
        ('CONCLUIDO', 'Concluido'),
    )

    numero_folio = models.CharField(max_length=10, unique=True)
    rfc = models.CharField(max_length=13)
    resolucion = models.TextField()
    contribuyente = models.CharField(max_length=200)
    dependencia = models.CharField(max_length=200)
    motivo = models.TextField()
    tema = models.ForeignKey(Tema, on_delete=models.PROTECT)
    tipo_firmado = models.CharField(max_length=10, choices=TIPO_FIRMADO)
    estatus = models.CharField(max_length=10, choices=ESTATUS, default='PENDIENTE')
    fecha_registro = models.DateTimeField(auto_now_add=True)
    usuario = models.ForeignKey('Usuario', on_delete=models.CASCADE)

    def __str__(self):
        return f"Folio {self.numero_folio}"
    
class ConsecutivoFolio(models.Model):
# Única fila para llevar el consecutivo global
    llave = models.CharField(max_length=20, unique=True, default='FOLIO')
    ultimo = models.PositiveIntegerField(default=0)
    def __str__(self):
        return f"{self.llave}: {self.ultimo}"

def user_tiene_bloqueo(user):
    """Bloquea si el usuario tiene algún folio PENDIENTE con antigüedad > 4 días."""
    limite = timezone.localdate() - timedelta(days=4)
    return Folio.objects.filter(usuario=user, estatus='PENDIENTE', fecha_registro__lt=limite).exists()