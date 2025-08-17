from django.db import migrations

def seed_consecutivo_folio(apps, schema_editor):
    ConsecutivoFolio = apps.get_model('folios', 'ConsecutivoFolio')
    # Crea el registro si no existe
    ConsecutivoFolio.objects.get_or_create(
        llave='FOLIO',
        defaults={'ultimo': 0}
    )

class Migration(migrations.Migration):

    dependencies = [
        ('folios', '0004_alter_folio_fecha_registro_alter_folio_tema'),
    ]

    operations = [
        migrations.RunPython(seed_consecutivo_folio, migrations.RunPython.noop),
    ]

