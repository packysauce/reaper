from django.db import models

# Create your models here.
class Policy(models.Model):
    TYPE_CHOICES = (
            ('WI', 'Windows'),
            ('UN', 'Unix'),
            ('DB', 'Database'),
            ('WF', 'Windows File'),
            )
    name = models.CharField(max_length=255)
    data = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=2, choices=TYPE_CHOICES)
    hash = models.CharField(max_length=40, unique=True)

class Template(models.Model):
    name = models.CharField(max_length=255)
    data = models.TextField()
    hash = models.CharField(max_length=40, unique=True)

class ScanConfig(models.Model):
    name = models.CharField(max_length=255)
    plugins = models.ManyToManyField('plugins.Plugin')
    policies = models.ManyToManyField('compliance.Policy')
    template = models.ForeignKey('compliance.Template')

class Target(models.Model):
    name = models.CharField(max_length=255)
    targets = models.TextField()
    hash = models.CharField(max_length=40, unique=True)

class Scan(models.Model):
    scan_config = models.ForeignKey('compliance.ScanConfig')
    targets = models.ForeignKey('compliance.Target')
    start = models.DateTimeField()
    stop = models.DateTimeField()

class Result(models.Model):
    scan = models.ForeignKey('compliance.Scan')
    ip_address = models.ForeignKey('devices.IpAddress')
    plugin = models.ForeignKey('plugins.Plugin')
    type = models.CharField(max_length = 25)
    description = models.TextField()

class ScheduledScan(models.Model):
    scan = models.ForeignKey('compliance.Scan', null=True)
    scan_config = models.ForeignKey('compliance.ScanConfig')
    targets = models.ForeignKey('compliance.Target')
    name = models.CharField(max_length=80)
    time = models.TimeField()
    sunday = models.BooleanField(default=False)
    monday = models.BooleanField(default=False)
    tuesday = models.BooleanField(default=False)
    wednesday = models.BooleanField(default=False)
    thursday = models.BooleanField(default=False)
    friday = models.BooleanField(default=False)
    saturday = models.BooleanField(default=False)
