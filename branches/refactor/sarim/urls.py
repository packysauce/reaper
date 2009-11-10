from django.conf.urls.defaults import *

urlpatterns = patterns('',
    url(r'^comments/add/(.+)/(.+)/$', 'sarim.ajax.add_comment', name='add_comment'),
    url(r'^$', 'sarim.views.index', name='index'),
)

