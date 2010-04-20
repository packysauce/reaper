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
    hash = models.CharField(max_length=40)

class Template(models.Model):
    name = models.CharField(max_length=255)
    data = models.TextField()
    hash = models.CharField(max_length=40)

class ScanConfig(models.Model):
    name = models.CharField(max_length=255)
    plugins = models.ManyToManyField('plugins.Plugin')
    policies = models.ManyToManyField('compliance.Policy')
    template = models.ForeignKey('compliance.Template')

class Scan(models.Model):
    scan_config = models.ForeignKey('compliance.ScanConfig')
    targets = models.TextField() #can't decide if I should m2m this with ip address... seems like that could get hairy fast
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
    name = models.CharField(max_length=80)
    time = models.TimeField()
    sunday = models.BooleanField(default=False)
    monday = models.BooleanField(default=False)
    tuesday = models.BooleanField(default=False)
    wednesday = models.BooleanField(default=False)
    thursday = models.BooleanField(default=False)
    friday = models.BooleanField(default=False)
    saturday = models.BooleanField(default=False)
