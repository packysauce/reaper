def get_hosts_by_user(username):
    import MySQLdb
    dbconn = MySQLdb.connect(user='secops', host='netwatcher5', db='gator2')
    c = dbconn.cursor()
    nresults = c.execute("SELECT fqdn FROM mac_assignment "+
            "LEFT JOIN fqdn USING (fqdn_index) "+
            "LEFT JOIN (mac_registration "+
            "    LEFT JOIN user USING (user_index)"+
            "    ) USING (mac_index) "+
            "WHERE user.username='%s'" % username)

    dbresults = [i[0].split('.jlab.org')[0].lower() for i in c.fetchall()]
    c.close()
    dbconn.close()

    if nresults > 0:
        return dbresults
    else:
        return ()

class Gator:
    """Runs a Gator query and caches the result"""
    building = ''
    first_seen = ''
    fqdn = ''
    ip = ''
    mac = ''
    jack = ''
    proptag = ''
    recently_seen = ''
    mtime = ''
    room = ''
    switch_name = ''
    switch_port = ''
    username = ''
    vlan = ''
    parsed = ''

    def __init__(self, id):
        """Initialize class with host, mac, or property tag"""
        import re, httplib

        lookup_type = 'host'

        #Check if id is an IP address
        if re.match(r'(\d{1,3}\.){3}\d{1,3}', id) or re.match(r'[\w-]*', id):
            lookup_type = 'host'
        elif re.match(r'[fF]4\d{3,6}', id):
            lookup_type = 'proptag'
        elif re.match(r'([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}',id) or re.match(r'([a-fA-F0-9]{4}.){2}[a-fA-F0-9]{4}',id) or re.match(r'[a-fA-F0-9]{12}',id):
            lookup_type = 'mac'
        else:
            raise ValueError('Invalid identifier specified')

        print lookup_type

        conn = httplib.HTTPSConnection('jnet.jlab.org')
        conn.request('get','/remote/query.php?type=%s&q=%s' % (lookup_type, id))
        r = conn.getresponse().read()

        try:
            self.building = re.search(r'<building>(.*)</building>',r).group(1)
            self.first_seen = re.search(r'<first_seen>(.*)</first_seen>',r).group(1)
            self.fqdn = re.search(r'<fqdn>(.*)</fqdn>',r).group(1)
            self.ip = re.search(r'<host_ip>(.*)</host_ip>',r).group(1)
            self.mac = re.search(r'<host_mac>(.*)</host_mac>',r).group(1)
            self.jack = re.search(r'<jack_name>(.*)</jack_name>',r).group(1)
            self.proptag = re.search(r'<proptag>(.*)</proptag>',r).group(1)
            self.recently_seen = re.search(r'<recently_seen>(.*)</recently_seen>',r).group(1)
            self.mtime = re.search(r'<reg_mtime>(.*)</reg_mtime>',r).group(1)
            self.room = re.search(r'<room_name>(.*)</room_name>',r).group(1)
            self.switch_name = re.search(r'<switch_name>(.*)</switch_name>',r).group(1)
            self.switch_port = re.search(r'<switch_port_name>(.*)</switch_port_name>',r).group(1)
            self.username = re.search(r'<username>(.*)</username>',r).group(1)
            self.vlan = re.search(r'<vlan_number>(.*)</vlan_number>',r).group(1)
        except:
            pass

