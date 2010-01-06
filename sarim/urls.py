from django.conf.urls.defaults import *
from reaper.sarim import views, ajax

urlpatterns = patterns('',
    url(r'^comments/add/(.+)/(.+)/$', ajax.add_comment, name='add_comment'),
    url(r'^$', views.index, name='index'),
)

