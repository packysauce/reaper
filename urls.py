import django.views.static
import os
from django.conf.urls.defaults import *
from django.views.generic.simple import direct_to_template
from django.conf import settings

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    (r'^userprofile/', include('userprofile.urls')),
    (r'^devices/', include('devices.urls')),
    (r'^vulns/', include('vulnerabilities.urls')),
    (r'^scans/', include('scans.urls')),
    (r'^plugins/', include('plugins.urls')),
    (r'^falsepositives/', include('falsepositives.urls')),
    (r'^subscriptions/', include('subscriptions.urls')),
    # Uncomment the next line to enable the admin:
    (r'^admin/', include(admin.site.urls)),
    
        # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    (r'^', include('reaper.sarim.urls')),
    
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),
)

if settings.DEBUG:
    urlpatterns += patterns('',
        url(r'^site_media/(?P<path>.*)$', django.views.static.serve,
            {'document_root': os.path.join(settings.PROJECT_ROOT,'common','static')}, name='static'),
        )
