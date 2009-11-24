from django.conf.urls.defaults import *
from plugins import views, ajax

urlpatterns = patterns('',
    url(r'^search/$', views.plugin_search, name='plugin_search'),
    url(r'^sift/$', ajax.autocomplete_search_plugins, name='plugin_ac'),
    url(r'^(\d*)/(.*)/$', views.plugin_info_view, name='plugin'),
)

