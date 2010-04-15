#!/usr/bin/python
import sys, os, sha, glob
from optparse import OptionParser
from django.utils.encoding import DjangoUnicodeDecodeError
try:
    sys.path.append('/opt/reaper')
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
    from compliance.models import *
    from django.db import IntegrityError
except:
    sys.stderr.write("There is a problem with the Django configuration, check path and verify setup\n")
    sys.exit()


def check_policy_type(code):
    if dict(Policy.TYPE_CHOICES).has_key(code):
        return True
    return False

def list_policies(*args, **kwargs):
    print "Code\tDescription"
    print "-----------------"
    for code, desc in Policy.TYPE_CHOICES:
        print "%s\t%s" % (code, desc)


parser = OptionParser(usage="%prog [-t] [-l] <file 1> .. <file N>\n\nThis script will import a number of scripts of the given type into the SARIM database.\nAll listed files must be of the same type.")
parser.add_option('-t', '--type', dest='type', help='Type of policy (default %default)', metavar='CODE', default="WI")
parser.add_option('-l', '--list-types', action='callback', callback=list_policies, help="List available policy types")
parser.add_option('-d', '--debug',dest="debug", action="store_true", help="Enable debug mode (show exceptions)")

(options, args) = parser.parse_args()

if not check_policy_type(options.type):
    sys.stderr.write("Invalid policy type, use the -l option to see a list of valid types\n")
    sys.exit()

for gl in args:
    files = glob.glob(gl)
    for filename in files:
        try:
            f = open(filename, 'r')
            data = f.read()
            f.close()
        except:
            sys.stderr.write("Unable to access %s, check permissions and try again\n" % sys.argv[1])

        sys.stdout.write(filename)
        try:
            p = Policy()
            p.name = os.path.basename(filename)
            p.hash = sha.new(data).hexdigest()
            p.data = data
            p.type = options.type
            p.save()
            sys.stdout.write("...OK\n")
        except DjangoUnicodeDecodeError, e:
            sys.stdout.write("...WARNING (Error decoding unicode)\n")
        except IntegrityError, e:
            sys.stdout.write("...ERROR (Duplicate hash exists)\n")
        except Exception, e:
            sys.stdout.write("...ERROR (Unknown)\n")
            if options.debug:
                sys.stdout.write(str(e))
