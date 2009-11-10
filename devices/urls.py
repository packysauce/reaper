from django.conf.urls.defaults import *
from devices import views
from sarim import ajax
urlpatterns = patterns('',
    url(r'^$', views.device_search, name='device_search'), 
    url(r'^(.+)/$', views.device_view, name='device'),
)

