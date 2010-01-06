from django.conf.urls.defaults import *
from userprofile import views

# Uncomment the next two lines to enable the admin:
#from django.contrib import admin
#admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    url(r'^$', views.index, name='profile_view'),
)
