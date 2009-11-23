from datetime import *
from utils.bobdb import *
from utils.djangolist import *
from django.db.models import Q
from devices.models import *

class FalsePositivesHelper(object):
    def __init__(self, ip=None, plugin=None):
        """Initializes the class with the requested data. If 'ip' is specified, then load only that IP's FP data.
        If plugin is specified, then load only that plugin's data.
        If neither are specified, load all the FalsePositive data.
        """
        self.__fplist = []

        if type(ip) == IpAddress:
            _ip = ip.ip
        else:
            _ip = ip

        #grab all of the false positives for the required criteria
        if _ip == None and plugin == None:
            self.__fplist = list(FalsePositive.objects.filter(active=True))
        elif plugin != None and ip == None:
            self.__fplist = list(FalsePositive.objects.filter(nessusid=int(plugin),active=True))
        elif _ip != None and plugin == None:
            self.__fplist = list(FalsePositive.objects.filter(includes__contains=anytoa(_ip),active=True))
        else:
            self.__fplist = list(FalsePositive.objects.filter(includes__contains=anytoa(_ip), nessusid=int(plugin),active=True))

        return

    @staticmethod
    def get_false_positives_by_ip(*args, **kwargs):
        if 'includes' in kwargs.keys():
            query = Q(includes__contains=kwargs['includes']) | Q(includes='ALL')
        elif 'excludes' in kwargs.keys():
            query = Q(excludes__contains=kwargs['excludes'])
        else:
            return []

        l = list(FalsePositive.objects.filter(query & Q(active=True)))
        return l

    @staticmethod
    def get_lists_from_fp(fp):
        """Returns a 2-tuple of lists containing the included and excluded IPs
        from a given False Positive object"""
        includes = list(fp.includes.split(','))
        if fp.excludes == '':
            excludes = []
        else:
            excludes = list(fp.excludes.split(','))

        if includes == 'ALL':
            return (includes, excludes)
        else:
            inc_set = set()
            for i in includes:
                inc_set.add(i)
            for e in excludes:
                try:
                    inc_set.remove(e)
                except KeyError, e:
                    pass

            return (list(inc_set), excludes)


    def __in_iplist(self, ip, fplist):
        fplistlower = fplist.lower()
        if "all" in fplistlower:
            return True
        if "none" in fplistlower:
            return False
        
        if ip in fplist.split(','):
            return True

        return False

    def is_falsepositive(self, ip, nessusid):
        """Checks the ip and nessusid combination against the data loaded to see if it is a false positive.
        """
        if type(ip) == int or isinstance(ip, basestring):
            _ip = anytoa(ip)
        elif type(ip) == ScanResults:
            _ip = anytoa(ScanResults.ip_id)
        elif type(ip) == IpAddress:
            _ip = ntoa(ip.ip)
        else:
            raise ValueError("Must specify IP as a number, string, or ScanResult")

        fpidx = get_index_by_attr(self.__fplist, "nessusid", long(nessusid))
        if fpidx == -1:
            return False

        curfp = self.__fplist[fpidx]


        #if the date's OK and the IP is in the lists, it's a false positive!
        if self.__in_iplist(_ip, curfp.includes) and not self.__in_iplist(_ip, curfp.excludes):
            if curfp.date_added > Plugin.objects.filter(nessusid=curfp.nessusid).latest().entered:
                return True

        #current FP is older than the newest version of the plugin
        # or the ip is not included in the false positive
        # or the ip is specifically excluded from the false positive
        return False
    
