from django.conf.urls.defaults import *
from reaper.scans import views

urlpatterns = patterns('',
    url(r'^(\d*)/$', views.scan_view, name='scan'),
    url(r'^search/$', views.scan_search, name='scan_search'),
)

