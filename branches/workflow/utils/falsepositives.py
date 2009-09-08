from sarimui.models import *
from datetime import *
from utils.bobdb import *
from utils.djangolist import *

class FalsePositivesHelper(object):
    def __init__(self, ip=None, plugin=None):
        """Initializes the class with the requested data. If 'ip' is specified, then load only that IP's FP data.
        If plugin is specified, then load only that plugin's data.
        If neither are specified, load all the FalsePositive data.
        """
        self.__fplist = []

        #grab all of the false positives for the required criteria
        if ip == None and plugin == None:
            self.__fplist = list(FalsePositive.objects.filter(active=True))
        elif plugin != None and ip == None:
            self.__fplist = list(FalsePositive.objects.filter(nessusid=int(plugin),active=True))
        elif ip != None and plugin == None:
            self.__fplist = list(FalsePositive.objects.filter(ip=anyton(ip),active=True))
        else:
            self.__fplist = list(FalsePositive.objects.filter(ip=anyton(ip), nessusid=int(plugin),active=True))

        return

    @staticmethod
    def get_lists_from_fp(fp):
        """Returns a 2-tuple of lists containing the included and excluded IPs
        from a given False Positive object"""
        includes = list(fp.includes.split(','))
        excludes = list(fp.excludes.split(','))

        from pprint import pprint as p

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
        if type(ip) == int or type(ip) == str:
            _ip = anytoa(ip)
        elif type(ip) == ScanResult:
            _ip = anytoa(ScanResult.ip_id)
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
    
