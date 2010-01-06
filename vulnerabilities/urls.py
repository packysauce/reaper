from django.conf.urls.defaults import *
from vulnerabilities import views

urlpatterns = patterns('',
    url(r'^by_vuln/$', views.ips_by_vuln, name='ips_by_vuln'),
    url(r'^by_ip/$', views.vulns_by_ip, name='vulns_by_ip'),
)

