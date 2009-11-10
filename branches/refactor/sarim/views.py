from django.http import *
from django.shortcuts import render_to_response
from django.core.urlresolvers import reverse

def index(request):
    return HttpResponseRedirect(reverse('ips_by_vuln'))
