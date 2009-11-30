from django.db import models
from django.contrib.contenttypes import generic
from utils.fields import SparseField
from sarim.models import Comment

# Create your models here.
class Plugin(models.Model):
    def __init__(self, *args, **kwargs):
        super(Plugin,self).__init__(*args, **kwargs)
        self.parsed = False
        self.descparts = {}

    def __parse_desc(self):
        #get everything ready to work on
        if self.parsed:
            return
        desc = self.description
        ldesc = desc.lower()
        index = []
        #words to look for
        words = ['synopsis','description','solution','risk factor']
        #build a list of tuples of format (<word position>, <word>)
        for word in words:
            try:
                index.append( (ldesc.index(word), word) )
            except:
                index.append( (-1, word) )
        #sort the aforementioned list according to word position
        import operator
        sindex = sorted(index, key=operator.itemgetter(0))

        for pos, word in sindex:
            #Get the tuple's position in the list of tuples
            mappos = sindex.index( (pos, word) )
            #-1 means the word wasn't found...
            if pos == -1:
                #All this does is go find the next word without a -1 position
                #and copy all of the text from the start of the description to the
                #first position found
                if word == 'description':
                    x = -1
                    for i in range(mappos,len(sindex)):
                        if sindex[i][0] != -1:
                            x = sindex[i][0]
                    s = desc[0:x]
                else:
                    continue
            else:
                if mappos == len(sindex)-1:
                    s = desc[pos+len(word):]
                else:
                    s = desc[pos+len(word):sindex[mappos+1][0]]

            #The nessus plugin info has some stupid escaping going on
            s = s.replace(':\\n\\n', '')
            s = s.replace('\\n', ' ')
            s = s.replace(': ', '', 1)
            #Take care of dictionary names with spaces in them
            self.descparts[word.replace(' ', '')] = s

        self.parsed = True

    def __get_synopsis(self):
        self.__parse_desc()
        if self.descparts.has_key('synopsis'):
            return self.descparts['synopsis']
        else:
            return None
    def __get_desc(self):
        self.__parse_desc()
        if self.descparts.has_key('description')
            return self.descparts['description']
        else:
            return None
    def __get_solution(self):
        self.__parse_desc()
        if self.descparts.has_key('solution')
            return self.descparts['solution']
        else:
            return None
    def __get_riskfactor(self):
        self.__parse_desc()
        if self.descparts.has_key('riskfactor')
            return self.descparts['riskfactor']
        else:
            return None

    desc = property(__get_desc)
    synopsis = property(__get_synopsis)
    solution = property(__get_solution)
    riskfactor = property(__get_riskfactor)

    def __unicode__(self):
        return u'nessus plugin {0}'.format(self.nessusid)
    id = models.IntegerField(primary_key=True)
    digest = models.CharField(max_length=192, primary_key=True)
    nessusid = models.IntegerField()
    name = models.TextField()
    version = models.CharField(max_length=96)
    summary = models.TextField()
    family = models.CharField(max_length=192)
    category = models.CharField(max_length=96)
    risk = models.CharField(max_length=384)
    cveid = models.TextField(blank=True)
    bugtraqid = models.TextField(blank=True)
    xref = models.TextField(blank=True)
    top20cves = models.TextField(blank=True)
    description = models.TextField(blank=True)
    configfile = models.TextField(blank=True)
    entered = models.DateTimeField(auto_now_add=True)
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        managed = False
        ordering = ['-entered']
        db_table = u'plugin'
        get_latest_by = u'entered'

class PluginDump(models.Model):
    id = models.IntegerField(primary_key=True)
    plugincount = models.IntegerField()
    pluginsadded = models.IntegerField(null=True, blank=True)
    pluginlist = SparseField(blank=True)
    digest = models.CharField(unique=True, max_length=120)
    source = models.ForeignKey('sarim.Source', db_column='sourceid')
    starttime = models.DateTimeField()
    endtime = models.DateTimeField(null=True, blank=True)
    plugins = models.ManyToManyField('Plugin', through='PluginDumpPlugin')
    comments = generic.GenericRelation('sarim.Comment')
    class Meta:
        managed = False
        db_table = u'plugindump'

class PluginDumpPlugin(models.Model):
    plugindump = models.ForeignKey('PluginDump', db_column='plugindumpid', primary_key=True)
    plugin = models.ForeignKey('Plugin', db_column='pluginid')
    class Meta:
        managed = False
        db_table = u'plugindumpplugin'
