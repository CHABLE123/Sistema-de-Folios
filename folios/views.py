from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
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
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from io import BytesIO
import pandas as pd
import xlsxwriter
from datetime import datetime  

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
    desde = request.GET.get('desde')  # 'YYYY-MM-DD' o ''
    hasta = request.GET.get('hasta')  # 'YYYY-MM-DD' o ''

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
    
    if desde:
        qs = qs.filter(fecha_registro__date__gte=desde)
    if hasta:
        qs = qs.filter(fecha_registro__date__lte=hasta)

    # >>> agregado para evitar NameError <<<
    context = {}
    context.update({'f_desde': desde or '', 'f_hasta': hasta or ''})

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
    # Base queryset + permisos por rol
    qs = Folio.objects.select_related('tema', 'usuario', 'concluido_por').all()
    if request.user.perfil in ['JEFE', 'OPERATIVO']:
        qs = qs.filter(usuario=request.user)

    # Filtros
    estatus = (request.GET.get('estatus') or '').strip()
    tema = (request.GET.get('tema') or '').strip()
    q = (request.GET.get('q') or '').strip()
    desde = (request.GET.get('desde') or '').strip()
    hasta = (request.GET.get('hasta') or '').strip()

    if estatus:
        qs = qs.filter(estatus=estatus)
    if tema:
        qs = qs.filter(tema_id=tema)
    if q:
        qs = qs.filter(
            Q(numero_folio__icontains=q) |
            Q(rfc__icontains=q) |
            Q(contribuyente__icontains=q) |
            Q(dependencia__icontains=q) |
            Q(motivo__icontains=q)
        )
    if desde:
        qs = qs.filter(fecha_registro__date__gte=desde)
    if hasta:
        qs = qs.filter(fecha_registro__date__lte=hasta)

    qs = qs.order_by('-numero_folio')

    # ---- DataFrame detalle
    rows = []
    for f in qs:
        rows.append({
            'Folio': f.numero_folio,
            'Fecha registro': f.fecha_registro,   # datetime (aware)
            'RFC': f.rfc,
            'Contribuyente': f.contribuyente,
            'Dependencia': f.dependencia,
            'Tema': f.tema.nombre if f.tema_id else '',
            'Tipo firmado': f.get_tipo_firmado_display(),
            'Estatus': 'Concluido' if f.estatus == 'CONCLUIDO' else 'Pendiente',
            'Usuario (emite)': f.usuario.nombre_completo() if f.usuario_id else '',
            'Fecha conclusión': f.fecha_conclusion,  # datetime (aware o None)
            'Concluido por': f.concluido_por.nombre_completo() if f.concluido_por_id else '',
        })
    df = pd.DataFrame(rows)

    # Writer (xlsxwriter). pandas necesita datetimes NAIVE antes de to_excel
    output = BytesIO()
    writer = pd.ExcelWriter(
        output,
        engine='xlsxwriter',
        engine_kwargs={'options': {'in_memory': True, 'remove_timezone': True}}
    )
    workbook = writer.book

    # Formatos
    fmt_header = workbook.add_format({'bold': True, 'bg_color': '#D9E1F2', 'border': 1})
    fmt_border = workbook.add_format({'border': 1})
    fmt_dt = workbook.add_format({'num_format': 'dd-mm-yy hh:mm', 'border': 1})

    # ---- Normalizar datetimes a NAIVE (sin tz) ANTES de to_excel
    if not df.empty:
        for col in ['Fecha registro', 'Fecha conclusión']:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce').dt.tz_localize(None)

    # ---- Hoja 1: Folios (detalle)
    sheet_detalle = 'Folios'
    if df.empty:
        df = pd.DataFrame(columns=[
            'Folio','Fecha registro','RFC','Contribuyente','Dependencia',
            'Tema','Tipo firmado','Estatus','Usuario (emite)','Fecha conclusión','Concluido por'
        ])

    df.to_excel(writer, sheet_name=sheet_detalle, index=False)
    ws = writer.sheets[sheet_detalle]

    # Encabezados con estilo
    for col, h in enumerate(df.columns):
        ws.write(0, col, h, fmt_header)

    # Reaplicar formato de fecha a columnas de fecha (pandas ya escribió los valores)
    # y aplicar bordes a TODAS las celdas, cuidando NaT/NaN.
    date_cols = {'Fecha registro', 'Fecha conclusión'}
    if not df.empty:
        for r in range(len(df)):
            for c, h in enumerate(df.columns):
                val = df.iloc[r, c]
                row_excel = r + 1  # por encabezado
                if h in date_cols:
                    if pd.notna(val):
                        # asegurar datetime naive
                        dt = pd.to_datetime(val, errors='coerce')
                        if pd.notna(dt):
                            ws.write_datetime(row_excel, c, dt.to_pydatetime().replace(tzinfo=None), fmt_dt)
                        else:
                            ws.write(row_excel, c, '', fmt_border)
                    else:
                        ws.write(row_excel, c, '', fmt_border)
                else:
                    # NO fecha: proteger contra NaT/NaN/None
                    if pd.isna(val):
                        ws.write(row_excel, c, '', fmt_border)
                    elif isinstance(val, (pd.Timestamp, datetime)):
                        # Si accidentalmente quedó un datetime en una col no-fecha
                        ws.write_datetime(row_excel, c, pd.to_datetime(val).to_pydatetime().replace(tzinfo=None), fmt_dt)
                    else:
                        ws.write(row_excel, c, val, fmt_border)

    # Ancho de columnas
    for c, h in enumerate(df.columns):
        series = df[h].astype(str) if not df.empty else pd.Series([h])
        width = min(40, max(len(str(h))+2, int(series.map(len).max())+2 if not df.empty else len(h)+2, 12))
        # para fechas, un poco más ancho
        ws.set_column(c, c, max(width, 18) if h in date_cols else width)

    # ---- Hojas de resumen (si hay datos)
    if not df.empty:
        piv1 = df.pivot_table(index='Estatus', values='Folio', aggfunc='count').rename(columns={'Folio':'Cantidad'}).reset_index()
        piv2 = df.pivot_table(index='Tema', values='Folio', aggfunc='count').rename(columns={'Folio':'Cantidad'}).reset_index().sort_values('Cantidad', ascending=False)
        piv3 = df.pivot_table(index='Usuario (emite)', values='Folio', aggfunc='count').rename(columns={'Folio':'Cantidad'}).reset_index().sort_values('Cantidad', ascending=False)
        piv4 = df.pivot_table(index='Concluido por', values='Folio', aggfunc='count').rename(columns={'Folio':'Cantidad'}).reset_index().sort_values('Cantidad', ascending=False)

        def write_df(sheet_name, dfi):
            dfi = dfi.fillna('')  # asegurar que no haya NaN/NaT en resúmenes
            dfi.to_excel(writer, sheet_name=sheet_name, index=False)
            w = writer.sheets[sheet_name]
            # Encabezados
            for col, h in enumerate(dfi.columns):
                w.write(0, col, h, fmt_header)
            # Bordes
            for r in range(len(dfi)):
                for c in range(len(dfi.columns)):
                    w.write(r+1, c, dfi.iloc[r, c], fmt_border)
            # Ancho
            for c, h in enumerate(dfi.columns):
                series = dfi[h].astype(str) if not dfi.empty else pd.Series([h])
                width = min(40, max(len(str(h))+2, int(series.map(len).max())+2 if not dfi.empty else len(h)+2, 12))
                w.set_column(c, c, width)

        write_df('Resumen por estatus', piv1)
        write_df('Resumen por tema', piv2)
        write_df('Resumen por usuario', piv3)
        write_df('Resumen por concluyente', piv4)

    # Cerrar y responder
    writer.close()
    output.seek(0)

    fecha_str = timezone.now().strftime('%Y%m%d_%H%M')
    response = HttpResponse(
        output.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename="folios_reporte_{fecha_str}.xlsx"'
    return response


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

@require_POST
@login_required
def folio_despachar(request, pk):
    if request.user.perfil != 'ADMIN':
        messages.error(request, 'Solo un Administrador puede despachar folios.')
        return redirect('folios_consulta')

    folio = get_object_or_404(Folio, pk=pk)

    if folio.estatus == 'CONCLUIDO':
        messages.info(request, f'El folio {folio.numero_folio} ya estaba concluido.')
        return redirect(request.META.get('HTTP_REFERER', 'folios_consulta'))

    # Cambiar a concluido y registrar quién/cuándo
    folio.estatus = 'CONCLUIDO'
    folio.fecha_conclusion = timezone.now()
    folio.concluido_por = request.user
    folio.save(update_fields=['estatus','fecha_conclusion','concluido_por'])

    messages.success(request, f'Folio {folio.numero_folio} despachado (concluido) por {folio.concluido_por.nombre_completo()}.')
    return redirect(request.META.get('HTTP_REFERER', 'folios_consulta'))

def _es_gestor(user):
    return user.perfil in ('ADMIN', 'SUBADMIN')

@login_required
def folio_editar(request, pk):
    folio = get_object_or_404(Folio, pk=pk)

    # Permiso de edición: Admin/Subadmin cualquiera; otros solo su propio folio
    if not _es_gestor(request.user) and folio.usuario_id != request.user.id:
        messages.error(request, 'No tienes permiso para editar este folio.')
        return redirect('folios_consulta')
    
    # Regla: si el folio está CONCLUIDO, solo ADMIN/SUBADMIN pueden editarlo
    if folio.estatus == 'CONCLUIDO' and not _es_gestor(request.user):
        messages.error(request, f'El folio {folio.numero_folio} está concluido y no puede editarse.')
        return redirect('folios_consulta')

    temas = Tema.objects.filter(activo=True).order_by('nombre')

    if request.method == 'POST':
        rfc = (request.POST.get('rfc') or '').strip()
        resolucion = (request.POST.get('resolucion') or '').strip()
        contribuyente = (request.POST.get('contribuyente') or '').strip()
        dependencia = (request.POST.get('dependencia') or '').strip()
        motivo = (request.POST.get('motivo') or '').strip()
        tema_id = request.POST.get('tema')
        tipo_firmado = request.POST.get('tipo_firmado')
        nuevo_estatus = request.POST.get('estatus')  # Solo Admin

        # Validaciones simples
        errores = []
        if not rfc: errores.append('RFC es obligatorio.')
        if not resolucion: errores.append('Resolución es obligatoria.')
        if not contribuyente: errores.append('Contribuyente es obligatorio.')
        if not dependencia: errores.append('Dependencia es obligatoria.')
        if not motivo: errores.append('Motivo es obligatorio.')
        if not tema_id: errores.append('Tema es obligatorio.')
        if not tipo_firmado: errores.append('Tipo de firmado es obligatorio.')

        try:
            tema_obj = Tema.objects.get(pk=tema_id, activo=True)
        except Tema.DoesNotExist:
            errores.append('El tema seleccionado no es válido o está inactivo.')
            tema_obj = None

        if errores:
            for e in errores:
                messages.error(request, e)
            # Volver a pintar con valores que intentó enviar
            return render(request, 'folios/folio_editar.html', {
                'f': folio,
                'temas': temas,
                'form': {
                    'rfc': rfc,
                    'resolucion': resolucion,
                    'contribuyente': contribuyente,
                    'dependencia': dependencia,
                    'motivo': motivo,
                    'tema_id': tema_id,
                    'tipo_firmado': tipo_firmado,
                    'estatus': nuevo_estatus or folio.estatus,
                },
                'es_admin': _es_gestor(request.user),
            })

        # Actualizar
        folio.rfc = rfc
        folio.resolucion = resolucion
        folio.contribuyente = contribuyente
        folio.dependencia = dependencia
        folio.motivo = motivo
        folio.tema = tema_obj
        folio.tipo_firmado = tipo_firmado

        era = folio.estatus

        # Solo Admin/Subadmin pueden cambiar estatus
        if _es_gestor(request.user) and nuevo_estatus in ('PENDIENTE','CONCLUIDO'):
            folio.estatus = nuevo_estatus
            if era != 'CONCLUIDO' and nuevo_estatus == 'CONCLUIDO':
                # Se acaba de concluir desde edición
                folio.fecha_conclusion = timezone.now()
                folio.concluido_por = request.user
            elif era == 'CONCLUIDO' and nuevo_estatus == 'PENDIENTE':
                # Reabierto → limpiamos los campos de conclusión
                folio.fecha_conclusion = None
                folio.concluido_por = None

        folio.save()
        messages.success(request, f'Folio {folio.numero_folio} actualizado correctamente.')
        return redirect('folios_consulta')

    # GET → pintar formulario con valores actuales
    return render(request, 'folios/folio_editar.html', {
        'f': folio,
        'temas': temas,
        'form': {
            'rfc': folio.rfc,
            'resolucion': folio.resolucion,
            'contribuyente': folio.contribuyente,
            'dependencia': folio.dependencia,
            'motivo': folio.motivo,
            'tema_id': str(folio.tema_id),
            'tipo_firmado': folio.tipo_firmado,
            'estatus': folio.estatus,
        },
        'es_admin': _es_gestor(request.user),
    })


@login_required
def mi_perfil(request):
    """Ver/actualizar datos del usuario logueado (nombre, apellidos, email)."""
    user: Usuario = request.user

    if request.method == 'POST':
        nombre = (request.POST.get('nombre') or '').strip()
        ap_pat = (request.POST.get('apellido_paterno') or '').strip()
        ap_mat = (request.POST.get('apellido_materno') or '').strip()
        email = (request.POST.get('email') or '').strip()

        errores = []
        if not nombre:
            errores.append('El nombre es obligatorio.')
        if not ap_pat:
            errores.append('El apellido paterno es obligatorio.')
        if not email:
            errores.append('El correo es obligatorio.')

        # Email único (si ya lo manejas único en BD, esto ayuda a mostrar mensaje amable)
        if email and Usuario.objects.exclude(pk=user.pk).filter(email__iexact=email).exists():
            errores.append('Ya existe otro usuario con ese correo.')

        if errores:
            for e in errores:
                messages.error(request, e)
        else:
            user.nombre = nombre
            user.apellido_paterno = ap_pat
            user.apellido_materno = ap_mat or None
            user.email = email
            user.save(update_fields=['nombre', 'apellido_paterno', 'apellido_materno', 'email'])
            messages.success(request, 'Datos actualizados correctamente.')

    # GET o POST con errores → render con datos actuales
    return render(request, 'folios/mi_perfil.html', {
        'u': request.user
    })


@login_required
@require_POST
def cambiar_password(request):
    """Cambiar contraseña del usuario actual (valida contraseña actual y políticas)."""
    user: Usuario = request.user
    actual = request.POST.get('password_actual') or ''
    nueva = request.POST.get('password_nueva') or ''
    confirmar = request.POST.get('password_confirmar') or ''

    if not user.check_password(actual):
        messages.error(request, 'La contraseña actual es incorrecta.')
        return redirect('mi_perfil')

    if not nueva or not confirmar:
        messages.error(request, 'Debes ingresar y confirmar la nueva contraseña.')
        return redirect('mi_perfil')

    if nueva != confirmar:
        messages.error(request, 'La nueva contraseña y su confirmación no coinciden.')
        return redirect('mi_perfil')

    try:
        validate_password(nueva, user=user)  # aplica validadores de Django
    except ValidationError as e:
        for msg in e.messages:
            messages.error(request, msg)
        return redirect('mi_perfil')

    user.set_password(nueva)
    user.save(update_fields=['password'])
    update_session_auth_hash(request, user)  # mantiene la sesión activa
    messages.success(request, 'Contraseña actualizada correctamente.')
    return redirect('mi_perfil')