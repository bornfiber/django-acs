# Generated by Django 4.2 on 2024-04-15 14:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('acs', '0026_acsdevicemodel_vendor_config_files'),
    ]

    operations = [
        migrations.AlterField(
            model_name='acsdevicemodel',
            name='vendor_config_files',
            field=models.CharField(blank=True, default=None, max_length=50),
            preserve_default=False,
        ),
    ]
