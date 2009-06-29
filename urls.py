from django.conf.urls.defaults import *
from django.contrib import databrowse
from sarimui.models import *
from sarimui import views

databrowse.site.register(Source)
databrowse.site.register(ConfigList)
databrowse.site.register(Hostname)
databrowse.site.register(HostSet)
databrowse.site.register(ImapLoginList)
databrowse.site.register(IpComments)
databrowse.site.register(IpHostname)
databrowse.site.register(Log)
databrowse.site.register(Mac)
databrowse.site.register(MacIp)
databrowse.site.register(Notes)
databrowse.site.register(Plugin)
databrowse.site.register(PluginDump)
databrowse.site.register(Scanner)
databrowse.site.register(ScanRun)
databrowse.site.register(ScanResults)
databrowse.site.register(ScanSet)
databrowse.site.register(Schedule)
databrowse.site.register(Top20Lists)
databrowse.site.register(Vlans)
databrowse.site.register(VlanScanState)

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    # (r'^reaper/', include('reaper.foo.urls')),
    (r'^db/(.*)$', databrowse.site.root),
    url(r'^ip/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/$', views.ip_view),
    url(r'^plugin/(\d*)$', views.plugin_view),
    url(r'^scan/(\d*)$', views.scan_view),
    url(r'^hostname/(.*)$', views.hostname_view),
    url(r'^mac/([a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2})$', views.mac_view),

    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/', include(admin.site.urls)),
)
