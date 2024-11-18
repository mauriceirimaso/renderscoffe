# Generated by Django 5.1.1 on 2024-09-30 19:57

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        # Coffetable model
        migrations.CreateModel(
            name='Coffetable',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=100, unique=True)),
                ('fullnames', models.CharField(max_length=100, null=True, blank=True)),
                ('password', models.CharField(max_length=100, null=True, blank=True)),
                ('profilephoto', models.CharField(max_length=255, default='profilephoto', null=True, blank=True)),
                ('membership', models.CharField(max_length=100, blank=True)),
                ('balance', models.FloatField(null=True, blank=True)),
            ],
        ),

        # Coffeproducts model
        migrations.CreateModel(
            name='Coffeproducts',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('coffekind', models.CharField(max_length=100, null=True, blank=True)),
                ('rating', models.FloatField(null=True, blank=True)),
                ('coffename', models.CharField(max_length=100, blank=True)),
                ('coffetype', models.CharField(max_length=100, blank=True)),
                ('coffephoto', models.CharField(max_length=255, null=True, blank=True)),
                ('price', models.FloatField(null=True, blank=True)),
            ],
        ),

        # Orders model
        migrations.CreateModel(
            name='Orders',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('orderid', models.CharField(unique=True, blank=True, max_length=100)),
                ('email', models.CharField(max_length=100, null=True, blank=True)),
                ('productname', models.CharField(max_length=100, null=True, blank=True)),
                ('producttype', models.CharField(max_length=100, null=True, blank=True)),
                ('status', models.CharField(max_length=100, blank=True)),
                ('quantity', models.IntegerField(null=True, blank=True)),
                ('price', models.FloatField(null=True, blank=True)),
                ('coffephoto', models.CharField(null=True, blank=True)),
                ('time', models.CharField(max_length=100, blank=True)),
                ('date', models.CharField(max_length=100, blank=True)),
                ('isread', models.BooleanField(max_length=100, blank=True)),
            ],
        ),

        # History model
        migrations.CreateModel(
            name='History',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('orderid', models.CharField(blank=True, max_length=100)),
                ('email', models.CharField(max_length=100, null=True, blank=True)),
                ('productname', models.CharField(max_length=100, null=True, blank=True)),
                ('producttype', models.CharField(max_length=100, null=True, blank=True)),
                ('status', models.CharField(max_length=100, blank=True)),
                ('quantity', models.IntegerField(null=True, blank=True)),
                ('price', models.FloatField(null=True, blank=True)),
                ('coffephoto', models.CharField(null=True, blank=True)),
                ('time', models.CharField(max_length=100, blank=True)),
                ('date', models.CharField(max_length=100, blank=True)),
                ('isread', models.BooleanField(max_length=100, blank=True)),
            ],
        ),

        # Notification model
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('notitype', models.CharField(blank=True, max_length=100)),
                ('notiid', models.CharField(max_length=100, null=True, blank=True)),
                ('email', models.CharField(max_length=100, null=True, blank=True)),
                ('notiphoto', models.CharField(null=True, blank=True)),
                ('date', models.CharField(null=True, blank=True)),
                ('time', models.CharField(null=True, blank=True)),
                ('isread', models.BooleanField(null=True, blank=True)),
            ],
        ),
    ]
