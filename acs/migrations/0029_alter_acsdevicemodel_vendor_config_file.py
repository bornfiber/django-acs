# Generated by Django 4.2 on 2024-04-16 09:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('acs', '0028_rename_vendor_config_files_acsdevicemodel_vendor_config_file'),
    ]

    operations = [
        migrations.AlterField(
            model_name='acsdevicemodel',
            name='vendor_config_file',
            field=models.CharField(blank=True, default='', max_length=50),
        ),
    ]