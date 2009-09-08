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
    url(r'^$', views.index, name='index'),
    url(r'^site_media/(?P<path>.*)/$', django.views.static.serve,
        {'document_root': 'C:/users/pdwhite/desktop/reaper/sarimui/static'}, name='static'),
    url(r'^devices/$', views.device_search, name='device_search'),
    url(r'^plugin/(\d*)/$', views.plugin_view, name='plugin'),
    url(r'^plugin_info/(\d*)/(.*)/$', views.plugin_info_view),
    url(r'^plugin_list/(\d*)/$', views.plugin_list_view),
    url(r'^vulns_by_ip/$', views.vulns_by_ip, name='vulns_by_ip'),
    url(r'^scan/(\d*)/$', views.scan_view, name='scan'),
    url(r'^false_positive/(\d*)/$', views.fp_view, name='fp_detail'),
    url(r'^false_positive/search/$', views.fp_search, name='fp_search'),
    url(r'^(.+)/$', views.device_view, name='device'),

    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/', include(admin.site.urls)),
)
