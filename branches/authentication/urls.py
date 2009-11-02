from django.conf.urls.defaults import *
from sarimui.models import *
from sarimui import views
from sarimui import ajax
import django.views.static
from django.views.generic.simple import direct_to_template

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    # (r'^reaper/', include('reaper.foo.urls')),
    url(r'^$', views.index, name='index'),
    url(r'^site_media/(?P<path>.*)$', django.views.static.serve,
        {'document_root': 'C:/users/pdwhite/desktop/reaper/sarimui/static'}, name='static'),
    url(r'^plugin/search/$', views.plugin_search, name='plugin_search'),
    url(r'^plugin/(\d*)/(.*)/$', views.plugin_info_view, name='plugin'),
    url(r'^devices/$', views.device_search, name='device_search'),
    url(r'^vulns_by_ip/$', views.vulns_by_ip, name='vulns_by_ip'),
    url(r'^scan/(\d*)/$', views.scan_view, name='scan'),
    url(r'^scan/search/$', views.scan_search, name='scan_search'),
    url(r'^loginrequired/$', direct_to_template, { 'template': 'access_denied.html'}),
    url(r'^false_positive/(\d*)/$', views.fp_view, name='fp_detail'),
    url(r'^false_positive/(\d*)/modify/$', views.fp_modify, name='fp_modify'),
    url(r'^false_positive/(\d*)/delete/$', views.fp_delete, name='fp_delete'),
    url(r'^false_positive/create/(\d*)/$', views.fp_create, name='fp_create'),
    url(r'^false_positive/create/$', views.fp_create_help, name="fp_create_help"),
    url(r'^false_positive/modify/$', ajax.fp_modify, name="fp_modify_ajax"),
    url(r'^false_positive/new/$', ajax.fp_create, name='fp_create_ajax'),
    url(r'^false_positive/search/$', views.fp_search, name='fp_search'),
    url(r'^comments/add/(.+)/(.+)/$', ajax.add_comment, name='add_comment'),

    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    (r'^admin/', include(admin.site.urls)),
    url(r'^(.+)/$', views.device_view, name='device'),
)
