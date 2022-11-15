# Generated by Django 2.2.7 on 2022-11-09 08:32

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('acs', '0014_auto_20221104_1334'),
    ]

    operations = [
        migrations.AddField(
            model_name='acsdevice',
            name='acs_full_parameters',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='acsdevice',
            name='acs_full_parameters_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='acsdevice',
            name='connection_request',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='acsdevice',
            name='get_full_parameters',
            field=models.BooleanField(default=False),
        ),
    ]
