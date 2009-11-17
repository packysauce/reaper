from django.conf.urls.defaults import *
from devices import views, ajax

urlpatterns = patterns('',
    url(r'^$', views.device_search, name='device_search'), 
    url(r'^sift/$', ajax.autocomplete_search_devices, name='device_ac'),
    

    #MUST BE LAST
    url(r'^(.+)/$', views.device_view, name='device'),
)

