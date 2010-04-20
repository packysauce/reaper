from django.conf.urls.defaults import *
from compliance import views, ajax

urlpatterns = patterns('',
    url(r'^$', views.index, name='compliance'), 
    url(r'^policies/$', views.policy_manager, name='compliance_policies'),
    url(r'^policies/upload/', ajax.upload_policy, name='compliance_policy_upload'),
    url(r'^policies/download/(\d+)', ajax.download_policy, name='compliance_policy_download'),
    url(r'^policies/delete/(\d+)', ajax.delete_policy, name='compliance_policy_delete'),
    url(r'^scans/$', views.scan_manager, name='compliance_scans'),
    url(r'^scans/schedule/$', views.scan_schedules, name='compliance_scan_schedule'),
    url(r'^scans/schedule/create', views.create_scan_schedule, name='compliance_create_scan_schedule'),
)
