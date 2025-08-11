from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Folio, Tema, ConsecutivoFolio, user_tiene_bloqueo
from .models import Usuario
from django.core.paginator import Paginator
from django.db.models import Q, ProtectedError
from django.views.decorators.http import require_POST, require_http_methods
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
    """
    Registro de folios con:
    - Bloqueo por >4 días pendientes (user_tiene_bloqueo)
    - Numeración consecutiva segura (select_for_update + get_or_create)
    - Temas activos en el select
    - Modal con número de folio generado
    """
    # Si el usuario está bloqueado, muestra aviso y no permite registrar
    if user_tiene_bloqueo(request.user):
        return render(request, 'folios/folio_bloqueado.html')

    # Temas activos para el select
    temas = Tema.objects.filter(activo=True).order_by('nombre')

    if request.method == 'POST':
        rfc = (request.POST.get('rfc') or '').strip()
        resolucion = (request.POST.get('resolucion') or '').strip()
        contribuyente = (request.POST.get('contribuyente') or '').strip()
        dependencia = (request.POST.get('dependencia') or '').strip()
        motivo = (request.POST.get('motivo') or '').strip()
        tema_id = request.POST.get('tema')
        tipo_firmado = request.POST.get('tipo_firmado')

        # Validaciones básicas
        if not (rfc and contribuyente and dependencia and resolucion and motivo and tema_id and tipo_firmado):
            messages.error(request, 'Todos los campos son obligatorios.')
            return render(request, 'folios/folio_registro.html', {'temas': temas})

        try:
            tema_obj = Tema.objects.get(pk=tema_id, activo=True)
        except Tema.DoesNotExist:
            messages.error(request, 'El tema seleccionado no es válido o está inactivo.')
            return render(request, 'folios/folio_registro.html', {'temas': temas})

        # Generar folio consecutivo de forma segura
        with transaction.atomic():
            # Lock de fila + creación si no existe
            consecutivo, _ = ConsecutivoFolio.objects.select_for_update().get_or_create(
                llave='FOLIO',
                defaults={'ultimo': 0}
            )
            consecutivo.ultimo += 1
            numero_folio = f"{consecutivo.ultimo:04d}"

            # Crear el folio (estatus por defecto en el modelo)
            Folio.objects.create(
                numero_folio=numero_folio,
                rfc=rfc,
                resolucion=resolucion,
                contribuyente=contribuyente,
                dependencia=dependencia,
                motivo=motivo,
                tema=tema_obj,
                tipo_firmado=tipo_firmado,
                usuario=request.user,
            )

            # Guardar el nuevo valor del consecutivo
            consecutivo.save()

        # Mostrar modal con el número de folio; dejar el form listo para uno nuevo
        return render(request, 'folios/folio_registro.html', {
            'temas': temas,
            'folio_creado': numero_folio
        })

    # GET
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

def _solo_gestores(user):
    return user.perfil in ('ADMIN', 'SUBADMIN')

@login_required
def temas_lista(request):
    if not _solo_gestores(request.user):
        messages.error(request, 'No tienes permiso para acceder a Temas.')
        # Redirige al dashboard correspondiente
        return redirect({
            'ADMIN': 'dashboard_admin',
            'SUBADMIN': 'dashboard_subadmin',
            'JEFE': 'dashboard_jefe',
            'OPERATIVO': 'dashboard_operativo'
        }.get(request.user.perfil, 'dashboard_operativo'))

    q = request.GET.get('q', '').strip()
    qs = Tema.objects.all()
    if q:
        qs = qs.filter(nombre__icontains=q)

    return render(request, 'folios/temas_lista.html', {
        'temas': qs,
        'q': q
    })

@login_required
@require_POST
def tema_crear(request):
    if not _solo_gestores(request.user):
        messages.error(request, 'No tienes permiso para crear temas.')
        return redirect('temas_lista')

    nombre = request.POST.get('nombre', '').strip()
    if not nombre:
        messages.error(request, 'El nombre es obligatorio.')
        return redirect('temas_lista')

    if Tema.objects.filter(nombre__iexact=nombre).exists():
        messages.error(request, 'Ya existe un tema con ese nombre.')
        return redirect('temas_lista')

    Tema.objects.create(nombre=nombre, activo=True)
    messages.success(request, 'Tema creado correctamente.')
    return redirect('temas_lista')

@login_required
@require_POST
def tema_actualizar(request, pk):
    if not _solo_gestores(request.user):
        messages.error(request, 'No tienes permiso para actualizar temas.')
        return redirect('temas_lista')

    tema = get_object_or_404(Tema, pk=pk)
    nombre = request.POST.get('nombre', '').strip()
    activo = True if request.POST.get('activo') == 'on' else False

    if not nombre:
        messages.error(request, 'El nombre es obligatorio.')
        return redirect('temas_lista')

    if Tema.objects.exclude(pk=tema.pk).filter(nombre__iexact=nombre).exists():
        messages.error(request, 'Ya existe otro tema con ese nombre.')
        return redirect('temas_lista')

    tema.nombre = nombre
    tema.activo = activo
    tema.save()
    messages.success(request, 'Tema actualizado correctamente.')
    return redirect('temas_lista')

@login_required
@require_POST
def tema_eliminar(request, pk):
    if not _solo_gestores(request.user):
        messages.error(request, 'No tienes permiso para eliminar temas.')
        return redirect('temas_lista')

    tema = get_object_or_404(Tema, pk=pk)
    try:
        tema.delete()
        messages.success(request, 'Tema eliminado correctamente.')
    except ProtectedError:
        messages.error(request, 'No se puede eliminar el tema porque está siendo usado por folios.')
    return redirect('temas_lista')
