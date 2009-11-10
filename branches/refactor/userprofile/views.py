from datetime import *
from django.http import *
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required, permission_required
from django.template import RequestContext
from sarim.models import *
from userprofile.models import *
from userprofile.forms import *
import pprint

@login_required
def index(request):
    user = request.user
    import datetime

    render_dict = { 'pagetitle': 'Preferences', 'profile': user.get_profile()}

    if request.method == "POST":
        update_up = UserProfileForm(request.POST, instance=user.get_profile())
        if update_up.is_valid():
            render_dict['success'] = ['Successfully updated profile!']
            update_up.save()
        else:
            render_dict['error'] = ['Unable to update profile']

    render_dict['activity'] = Activity.objects.filter(user = user, timestamp__gte = datetime.datetime.now() - datetime.timedelta(days=30) )
    render_dict['form'] = UserProfileForm(instance=user.get_profile())
    
    return render_to_response('userprofile/view_profile.html', render_dict, context_instance= RequestContext(request))
