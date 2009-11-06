from django.conf.urls.defaults import *
from reaper.plugins import views

urlpatterns = patterns('',
    url(r'^search/$', views.plugin_search, name='plugin_search'),
    url(r'^(\d*)/(.*)/$', views.plugin_info_view, name='plugin'),
)

