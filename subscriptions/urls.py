from django.conf.urls.defaults import *
from subscriptions import views

urlpatterns = patterns('',
    url('^$',views.edit_subscriptions, name='edit_subscriptions'),
)
