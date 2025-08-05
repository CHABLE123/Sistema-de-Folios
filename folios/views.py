from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from .models import Folio
from .models import Usuario

def login_view(request):
    if request.method == 'POST':
        numero_empleado = request.POST.get('numero_empleado')
        password = request.POST.get('password')
        user = authenticate(request, numero_empleado=numero_empleado, password=password)

        if user is not None:
            login(request, user)
            if user.perfil == 'ADMIN':
                return redirect('dashboard_admin')
            elif user.perfil == 'SUBADMIN':
                return redirect('dashboard_subadmin')
            elif user.perfil == 'JEFE':
                return redirect('dashboard_jefe')
            else:
                return redirect('dashboard_operativo')
        else:
            messages.error(request, 'Credenciales incorrectas')
            return redirect('login')

    return render(request, 'folios/login.html')

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def dashboard_admin(request):
    total_folios = Folio.objects.all().count()
    pendientes = Folio.objects.filter(estatus='PENDIENTE').count()
    concluidos = Folio.objects.filter(estatus='CONCLUIDO').count()

    context = {
        'total_folios': total_folios,
        'pendientes': pendientes,
        'concluidos': concluidos,
    }

    return render(request, 'folios/dashboard_admin.html', context)

@login_required
def dashboard_subadmin(request):
    total_folios = Folio.objects.all().count()
    pendientes = Folio.objects.filter(estatus='PENDIENTE').count()
    concluidos = Folio.objects.filter(estatus='CONCLUIDO').count()

    context = {
        'total_folios': total_folios,
        'pendientes': pendientes,
        'concluidos': concluidos,
    }

    return render(request, 'folios/dashboard_subadmin.html', context)


def dashboard_jefe(request):
    return HttpResponse("Dashboard Jefe de Departamento")

def dashboard_operativo(request):
    return HttpResponse("Dashboard Operativo")

@login_required
def registrar_usuario(request):
    if request.user.perfil not in ['ADMIN', 'SUBADMIN']:
        messages.error(request, 'No tienes permiso para acceder a esta página.')
        return redirect('login')  # O redirige al dashboard correspondiente

    if request.method == 'POST':
        nombre = request.POST.get('nombre')
        ap_pat = request.POST.get('apellido_paterno')
        ap_mat = request.POST.get('apellido_materno')
        rfc = request.POST.get('rfc')
        numero = request.POST.get('numero_empleado')
        email = request.POST.get('email')
        password = request.POST.get('password')
        perfil = request.POST.get('perfil')

        if Usuario.objects.filter(rfc=rfc).exists():
            messages.error(request, 'El RFC ya está registrado.')
        elif Usuario.objects.filter(numero_empleado=numero).exists():
            messages.error(request, 'El número de empleado ya está registrado.')
        else:
            user = Usuario.objects.create_user(
                numero_empleado=numero,
                email=email,
                password=password,
                nombre=nombre,
                apellido_paterno=ap_pat,
                apellido_materno=ap_mat,
                rfc=rfc,
                perfil=perfil
            )
            messages.success(request, 'Usuario registrado exitosamente.')
            return redirect('registrar_usuario')

    return render(request, 'folios/registrar_usuario.html')

