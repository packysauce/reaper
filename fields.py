from django.db import models
from django.db.models import Q
from django.core.exceptions import *

class SparseField(models.TextField):
    """Field used to tie sparse strings to many database objects.
    Sparse strings look like '1,2,3,6,8-12,15'
    """

    __metaclass__ = models.SubfieldBase

    def __desparse__(self, sparse_string):
        result = []
        for item in sparse_string.split(','):
            parts = item.split('-')
            if len(parts) == 1:
                result.append(int(parts[0]))
            elif len(parts) == 2:
                [result.append(i) for i in range(int(parts[0]),int(parts[1])+1)]

        return sorted(result)

    def __ensparse__(self,list):
        _list = sorted(list)
        tmp = dict()

        for i in range(0,len(_list)):
            try: tmp[_list[i]-i]
            except: tmp[_list[i]-i] = []

            tmp[_list[i]-i].append(_list[i])

        result = ''
        for i in sorted(tmp):
            if len(tmp[i]) > 1:
                result += '%s-%s,' % (tmp[i][0],tmp[i][-1])
            else:
                result += '%s,' % tmp[i][0]

        return result[:-1]
        
    def __init__(self, *args, **kwargs):
        try:
            if args[0].__class__ == models.Model.__class__:
                self.__model_link_type__ = args[0]
                self.__model_remote_column__ = kwargs['link_on']
                del kwargs['link_on']
            else:
                raise FieldError('Linked model error')
        except:
            raise FieldError("Linked model error")

        super(SparseField, self).__init__(*args, **kwargs)
        self.cached = False
        self.cache = []

    def to_python(self, value):
        return self.__desparse__(value)
    
    def get_db_prep_value(self, value):
        return self.__ensparse__(value)
