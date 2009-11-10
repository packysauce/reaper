from django.conf.urls.defaults import *
from reaper.userprofile import views

# Uncomment the next two lines to enable the admin:
#from django.contrib import admin
#admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    url(r'^$', views.index, name='profile_view'),
    url(r'^subscriptions/$', include('subscriptions.urls')),
)
