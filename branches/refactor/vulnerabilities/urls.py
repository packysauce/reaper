from django.conf.urls.defaults import *
from reaper.vulnerabilities import views

urlpatterns = patterns('',
    url(r'^ips_by_vuln/$', views.ips_by_vuln, name='ips_by_vuln'),
    url(r'^vulns_by_ip/$', views.vulns_by_ip, name='vulns_by_ip'),
)

