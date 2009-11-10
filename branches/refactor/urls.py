import django.views.static
from django.conf.urls.defaults import *
from django.views.generic.simple import direct_to_template

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    (r'^$', include('reaper.sarim.urls')),
    (r'^userprofile/', include('reaper.userprofile.urls')),
    (r'^devices/', include('reaper.devices.urls')),
    (r'^vulns/', include('reaper.vulnerabilities.urls')),
    (r'^scans/', include('reaper.scans.urls')),
    (r'^plugins/', include('reaper.plugins.urls')),
    (r'^falsepositives/', include('reaper.falsepositives.urls')),

    url(r'^site_media/(?P<path>.*)$', django.views.static.serve,
        {'document_root': 'C:/users/pdwhite/desktop/reaper/common/static'}, name='static'),
        # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    (r'^admin/', include(admin.site.urls)),
)
