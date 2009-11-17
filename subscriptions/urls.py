from django.conf.urls.defaults import *
from subscriptions import views, ajax

urlpatterns = patterns('',
    url('^subscribe/$', ajax.create_subscription, name='subscribe'),
    url('^unsubscribe/$', ajax.delete_subscription, name='unsubscribe'),
    url('^$',views.edit_subscriptions, name='edit_subscriptions'),
)
