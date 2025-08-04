from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.http import HttpResponse

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

def dashboard_admin(request):
    return HttpResponse("Dashboard Administrador")

def dashboard_subadmin(request):
    return HttpResponse("Dashboard Subadministrador")

def dashboard_jefe(request):
    return HttpResponse("Dashboard Jefe de Departamento")

def dashboard_operativo(request):
    return HttpResponse("Dashboard Operativo")
