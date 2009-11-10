from django.conf.urls.defaults import *
from reaper.falsepositives import views, ajax

urlpatterns = patterns('',
    url(r'^(\d*)/$', views.fp_view, name='fp_detail'),
    url(r'^(\d*)/modify/$', views.fp_modify, name='fp_modify'),
    url(r'^(\d*)/delete/$', views.fp_delete, name='fp_delete'),
    url(r'^create/(\d*)/$', views.fp_create, name='fp_create'),
    url(r'^create/$', views.fp_create_help, name="fp_create_help"),
    url(r'^modify/$', ajax.fp_modify, name="fp_modify_ajax"),
    url(r'^new/$', ajax.fp_create, name='fp_create_ajax'),
    url(r'^search/$', views.fp_search, name='fp_search'),
)

