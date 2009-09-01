from django.conf.urls.defaults import *
from sarimui.models import *
from sarimui import views
import django.views.static

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    # (r'^reaper/', include('reaper.foo.urls')),
    url(r'^$', views.index),
    url(r'^site_media/(?P<path>.*)/$', django.views.static.serve,
        {'document_root': 'C:/users/pdwhite/desktop/reaper/sarimui/static'}),
    url(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/$', views.ip_view),
    url(r'^([a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2})/$', views.mac_view),
    url(r'^plugin/(\d*)/$', views.plugin_view),
    url(r'^plugin_info/(\d*)/(.*)/$', views.plugin_info_view),
    url(r'^plugin_list/(\d*)/$', views.plugin_list_view),
    url(r'^vulns_by_ip/$', views.vulns_by_ip),
    url(r'^scan/(\d*)/$', views.scan_view),
    url(r'^dashboard/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/$', views.dashboard_ip_view),
    url(r'^dashboard/([a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2})/$', views.dashboard_mac_view),
    url(r'^dashboard/(.+)/$', views.dashboard_host_view),
    url(r'^(.+)/$', views.hostname_view),

    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/', include(admin.site.urls)),
)
