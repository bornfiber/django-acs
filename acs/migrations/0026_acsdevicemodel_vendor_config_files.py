# Generated by Django 4.2 on 2024-04-15 12:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('acs', '0025_acsdevice_desired_preconfig_level'),
    ]

    operations = [
        migrations.AddField(
            model_name='acsdevicemodel',
            name='vendor_config_files',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
    ]
