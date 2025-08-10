from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Folio, Tema, ConsecutivoFolio, user_tiene_bloqueo
from .models import Usuario
from django.core.paginator import Paginator
from django.db.models import Q
from django.views.decorators.http import require_POST
from django.db import transaction
from django.utils import timezone
from io import BytesIO
import pandas as pd

@login_required
@require_POST
def usuario_toggle_activo(request, pk):
    if request.user.perfil not in ['ADMIN', 'SUBADMIN']:
        messages.error(request, 'No tienes permiso para esta acción.')
        return redirect(_redir_por_perfil(request.user))

    u = get_object_or_404(Usuario, pk=pk)

    # Protecciones
    if u.pk == request.user.pk:
        messages.error(request, 'No puedes desactivar tu propio usuario.')
        return redirect('usuarios_lista')

    # Solo ADMIN puede tocar superusuarios
    if u.is_superuser and request.user.perfil != 'ADMIN':
        messages.error(request, 'Solo un Administrador puede activar/desactivar a un superusuario.')
        return redirect('usuarios_lista')

    u.is_active = not u.is_active
    u.save()
    messages.success(request, f"Usuario {'activado' if u.is_active else 'desactivado'} correctamente.")
    return redirect('usuarios_lista')


@login_required
@require_POST
def usuario_eliminar(request, pk):
    # Hard delete solo ADMIN
    if request.user.perfil != 'ADMIN':
        messages.error(request, 'Solo un Administrador puede eliminar usuarios.')
        return redirect(_redir_por_perfil(request.user))

    u = get_object_or_404(Usuario, pk=pk)

    # Protecciones
    if u.pk == request.user.pk:
        messages.error(request, 'No puedes eliminar tu propio usuario.')
        return redirect('usuarios_lista')

    if u.is_superuser:
        messages.error(request, 'No se permite eliminar superusuarios.')
        return redirect('usuarios_lista')

    u.delete()
    messages.success(request, 'Usuario eliminado definitivamente.')
    return redirect('usuarios_lista')


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

@login_required
def dashboard_jefe(request):
    qs = Folio.objects.filter(usuario=request.user)
    context = {
        'total_folios': qs.count(),
        'pendientes': qs.filter(estatus='PENDIENTE').count(),
        'concluidos': qs.filter(estatus='CONCLUIDO').count(),
    }
    return render(request, 'folios/dashboard_jefe.html', context)

@login_required
def dashboard_operativo(request):
    qs = Folio.objects.filter(usuario=request.user)
    context = {
        'total_folios': qs.count(),
        'pendientes': qs.filter(estatus='PENDIENTE').count(),
        'concluidos': qs.filter(estatus='CONCLUIDO').count(),
    }
    return render(request, 'folios/dashboard_operativo.html', context)



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

def _redir_por_perfil(user):
    return {
        'ADMIN': 'dashboard_admin',
        'SUBADMIN': 'dashboard_subadmin',
        'JEFE': 'dashboard_jefe',
        'OPERATIVO': 'dashboard_operativo'
    }.get(user.perfil, 'login')

@login_required
def usuarios_lista(request):
    if request.user.perfil not in ['ADMIN', 'SUBADMIN']:
        messages.error(request, 'No tienes permiso para acceder a esta página.')
        return redirect(_redir_por_perfil(request.user))

    q = request.GET.get('q', '').strip()
    orden = request.GET.get('orden', 'numero_empleado')

    # Asegura que el orden coincida con campos REALES del modelo
    campos_validos = {'numero_empleado', 'nombre', 'perfil'}
    if orden not in campos_validos:
        orden = 'numero_empleado'

    qs = Usuario.objects.all().order_by(orden)

    if q:
        qs = qs.filter(
            Q(numero_empleado__icontains=q) |
            Q(nombre__icontains=q) |
            Q(apellido_paterno__icontains=q) |
            Q(apellido_materno__icontains=q) |
            Q(rfc__icontains=q) |
            Q(email__icontains=q)
        )

    paginator = Paginator(qs, 10)
    page_number = request.GET.get('page')
    usuarios = paginator.get_page(page_number)

    return render(request, 'folios/usuarios_lista.html', {
        'usuarios': usuarios,   # <-- clave
        'q': q,
        'orden': orden
    })

@login_required
def usuario_actualizar(request, pk):
    if request.user.perfil not in ['ADMIN', 'SUBADMIN']:
        messages.error(request, 'No tienes permiso para esta acción.')
        return redirect(_redir_por_perfil(request.user))

    u = get_object_or_404(Usuario, pk=pk)

    if request.method == 'POST':
        nombre = request.POST.get('nombre', '').strip()
        ap_pat = request.POST.get('apellido_paterno', '').strip()
        ap_mat = request.POST.get('apellido_materno', '').strip()
        rfc = request.POST.get('rfc', '').strip()
        numero = request.POST.get('numero_empleado', '').strip()
        email = request.POST.get('email', '').strip()
        perfil = request.POST.get('perfil', '').strip()
        password = request.POST.get('password', '').strip()

        # Unicidad excluyendo el propio registro
        if Usuario.objects.exclude(pk=u.pk).filter(rfc=rfc).exists():
            messages.error(request, 'El RFC ya está registrado en otro usuario.')
        elif Usuario.objects.exclude(pk=u.pk).filter(numero_empleado=numero).exists():
            messages.error(request, 'El número de empleado ya está registrado en otro usuario.')
        elif Usuario.objects.exclude(pk=u.pk).filter(email=email).exists():
            messages.error(request, 'El correo ya está registrado en otro usuario.')
        else:
            u.nombre = nombre
            u.apellido_paterno = ap_pat
            u.apellido_materno = ap_mat
            u.rfc = rfc
            u.numero_empleado = numero
            u.email = email
            u.perfil = perfil
            if password:
                u.set_password(password)  # solo si se envía
            u.save()
            messages.success(request, 'Usuario actualizado correctamente.')

        # Regresa a la lista preservando búsqueda/página si venían en el referer
        return redirect('usuarios_lista')

    # Si viniera GET, podrías retornar JSON, pero el flujo es por POST desde el modal
    return redirect('usuarios_lista')

@login_required
@require_POST
def usuario_toggle_activo(request, pk):
    if request.user.perfil not in ['ADMIN', 'SUBADMIN']:
        messages.error(request, 'No tienes permiso para esta acción.')
        return redirect(_redir_por_perfil(request.user))

    u = get_object_or_404(Usuario, pk=pk)

    # Protecciones
    if u.pk == request.user.pk:
        messages.error(request, 'No puedes desactivar tu propio usuario.')
        return redirect('usuarios_lista')

    # Solo ADMIN puede tocar superusuarios
    if u.is_superuser and request.user.perfil != 'ADMIN':
        messages.error(request, 'Solo un Administrador puede activar/desactivar a un superusuario.')
        return redirect('usuarios_lista')

    u.is_active = not u.is_active
    u.save()
    messages.success(request, f"Usuario {'activado' if u.is_active else 'desactivado'} correctamente.")
    return redirect('usuarios_lista')


@login_required
@require_POST
def usuario_eliminar(request, pk):
    # Hard delete solo ADMIN
    if request.user.perfil != 'ADMIN':
        messages.error(request, 'Solo un Administrador puede eliminar usuarios.')
        return redirect(_redir_por_perfil(request.user))

    u = get_object_or_404(Usuario, pk=pk)

    # Protecciones
    if u.pk == request.user.pk:
        messages.error(request, 'No puedes eliminar tu propio usuario.')
        return redirect('usuarios_lista')

    if u.is_superuser:
        messages.error(request, 'No se permite eliminar superusuarios.')
        return redirect('usuarios_lista')

    u.delete()
    messages.success(request, 'Usuario eliminado definitivamente.')
    return redirect('usuarios_lista')

@login_required
def folio_registro(request):
    # Roles con permiso a registrar folios: todos, pero con bloqueo si tienen >4 días pendientes
    if user_tiene_bloqueo(request.user):
        # Mostrar alerta y no permitir registrar
        return render(request, 'folios/folio_bloqueado.html')

    temas = Tema.objects.all().order_by('nombre')

    if request.method == 'POST':
        rfc = request.POST.get('rfc', '').strip()
        resolucion = request.POST.get('resolucion', '').strip()
        contribuyente = request.POST.get('contribuyente', '').strip()
        dependencia = request.POST.get('dependencia', '').strip()
        motivo = request.POST.get('motivo', '').strip()
        tema_id = request.POST.get('tema')
        tipo_firmado = request.POST.get('tipo_firmado')

        # Generar folio consecutivo en transacción
        with transaction.atomic():
            c = ConsecutivoFolio.objects.select_for_update().get(llave='FOLIO')
            c.ultimo += 1
            numero_folio = f"{c.ultimo:04d}"
            # Crear folio
            Folio.objects.create(
                numero_folio=numero_folio,
                rfc=rfc,
                resolucion=resolucion,
                contribuyente=contribuyente,
                dependencia=dependencia,
                motivo=motivo,
                tema=Tema.objects.get(pk=tema_id),
                tipo_firmado=tipo_firmado,
                usuario=request.user,
            )
            c.save()

        # Mostrar modal con número de folio
        return render(request, 'folios/folio_registro.html', {
            'temas': temas,
            'folio_creado': numero_folio
        })

    return render(request, 'folios/folio_registro.html', {'temas': temas})


@login_required
def folios_consulta(request):
    # Filtros
    estatus = request.GET.get('estatus', '')
    tema_id = request.GET.get('tema', '')
    q = request.GET.get('q', '').strip()

    # Visibilidad por rol
    if request.user.perfil in ['ADMIN', 'SUBADMIN']:
        qs = Folio.objects.select_related('tema', 'usuario').all()
    else:
        qs = Folio.objects.select_related('tema', 'usuario').filter(usuario=request.user)

    if estatus:
        qs = qs.filter(estatus=estatus)
    if tema_id:
        qs = qs.filter(tema_id=tema_id)
    if q:
        qs = qs.filter(
            models.Q(numero_folio__icontains=q) |
            models.Q(rfc__icontains=q) |
            models.Q(contribuyente__icontains=q) |
            models.Q(dependencia__icontains=q) |
            models.Q(motivo__icontains=q)
        )

    temas = Tema.objects.all().order_by('nombre')
    return render(request, 'folios/folios_consulta.html', {
        'temas': temas,
        'folios': qs.order_by('-fecha_registro', '-id'),
        'f_estatus': estatus,
        'f_tema': tema_id,
        'q': q
    })


@login_required
def folios_exportar_excel(request):
    # Los mismos filtros que en la vista de consulta
    estatus = request.GET.get('estatus', '')
    tema_id = request.GET.get('tema', '')
    q = request.GET.get('q', '').strip()

    if request.user.perfil in ['ADMIN', 'SUBADMIN']:
        qs = Folio.objects.select_related('tema', 'usuario').all()
    else:
        qs = Folio.objects.select_related('tema', 'usuario').filter(usuario=request.user)

    if estatus:
        qs = qs.filter(estatus=estatus)
    if tema_id:
        qs = qs.filter(tema_id=tema_id)
    if q:
        qs = qs.filter(
            models.Q(numero_folio__icontains=q) |
            models.Q(rfc__icontains=q) |
            models.Q(contribuyente__icontains=q) |
            models.Q(dependencia__icontains=q) |
            models.Q(motivo__icontains=q)
        )

    # Construir DataFrame
    data = []
    for f in qs.order_by('numero_folio'):
        data.append({
            'Folio': f.numero_folio,
            'RFC': f.rfc,
            'Resolución': f.resolucion,
            'Contribuyente': f.contribuyente,
            'Dependencia': f.dependencia,
            'Motivo': f.motivo,
            'Tema': f.tema.nombre,
            'Tipo firmado': dict(Folio.TIPO_FIRMADO)[f.tipo_firmado],
            'Estatus': dict(Folio.ESTATUS)[f.estatus],
            'Fecha registro': f.fecha_registro.strftime('%Y-%m-%d'),
            'Usuario': f.usuario.numero_empleado,
        })
    df = pd.DataFrame(data)

    # Exportar a XLSX en memoria
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Folios')
    output.seek(0)

    resp = HttpResponse(
        output.getvalue(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    resp['Content-Disposition'] = f'attachment; filename="folios_{timezone.now().date()}.xlsx"'
    return resp

