from django.conf.urls.defaults import *
from reaper.devices import views

urlpatterns = patterns('',
    url(r'^/$', views.device_search, name='device_search'), 
    url(r'^(.+)/$', views.device_view, name='device'),
)

