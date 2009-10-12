from django.http import HttpResponseRedirect
from functools import wraps
from utils.gatorlink import get_hosts_by_user
from utils.bobdb import *
from sarimui.models import *

#Helper decorator for creating new permissions.
def permission(permission_tester):
    @wraps(permission_tester)
    def view_decorator(view_function):
        @wraps(view_decorator)
        def decorated_view(request, *args, **kwargs):
            if permission_tester(request, *args, **kwargs):
                view_result = view_function(request, *args, **kwargs)
            else:
                try:
                    request.user.message_set.create(message="Sorry, you don't have the necessary permissions to view that page.")
                except: pass
                view_result = HttpResponseRedirect("/")
            return view_result
        return decorated_view
    return view_decorator

@permission
def user_owns_machine(request, *args, **kwargs):
    if request.user.is_staff:
        print "user is staff or superuser"
        return True

    import subprocess, re, socket
    
    what = args[0]
    if SARIMUI_IP_RE.match(what):
        #it's an IP address, get it into a hostname
        try:
            hostname = socket.gethostbyaddr(what)[0].lower()
        except:
            #probably host not found
            return False

    elif SARIMUI_SHORT_IP_RE.match(what):
        #it's a short IP, add 129.57 and turn it into a hostname
        try:
            hostname = socket.gethostbyaddr('129.57.' + what)[0].lower()
        except:
            return False

    elif SARIMUI_MAC_RE.match(what):
        #it's a MAC, turn it into a hostname
        hostname = IpHostname.objects.filter(ip__macip__mac__mac='00:11:43:22:69:48').latest().hostname.hostname
        hostname = hostname.strip().lower()
    else:
        #assume it's a hostname
        hostname = what.lower()

    print 'testing', hostname, 'against', [i for i in get_hosts_by_user(request.user)]
    if hostname in [i for i in get_hosts_by_user(request.user)]:
        return True
    else:
        return False
