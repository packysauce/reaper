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
    url(r'^scans/configs/$', views.scan_configurations, name='compliance_scan_configurations'),
    url(r'^scans/configs/create', ajax.create_scanconfig, name='compliance_create_scan_config'),
    url(r'^scans/configs/delete/(\d+)', ajax.delete_scanconfig, name='compliance_delete_scan_config'),
    url(r'^scans/targets/$', views.scan_targets, name='compliance_scan_targets'),
    url(r'^scans/targets/create', ajax.create_targets, name='compliance_create_targets'),
    url(r'^scans/targets/delete/(\d+)', ajax.delete_targets, name='compliance_delete_targets'),
    url(r'^scans/templates/$', views.scan_templates, name='compliance_scan_templates'),
    url(r'^scans/templates/create', ajax.create_template, name='compliance_create_template'),
    url(r'^scans/templates/delete/(\d+)', ajax.delete_template, name='compliance_delete_template'),
)
