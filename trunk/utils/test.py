


def z(list):
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

def q(list):
    _list = sorted(list)
    tmp = ''
    in_range = False
    last = _list[0]-1

    for i in range(0,len(_list)):
        if _list[i] - last == 1:
            if not in_range:
                in_range = True
                tmp = tmp + '%s' % _list[i]
        else:
            if in_range:
                in_range = False
                tmp = tmp + '-%s,%s' % (last, _list[i])
            else:
                tmp = tmp + ',%s' % _list[i]
        last = _list[i]

    return tmp

def r(list):
    _list = sorted(list)
    tmp = ''
    in_range = False
    for i in range(0,len(_list)):
        if (_list[i+1]-_list[i]) == 1 and not in_range:
            tmp = tmp + '%s-' % _list[i]
            in_range = True
        elif (_list[i+1]-_list[i]) > 1:
            if range_between:
                range_between = False
                tmp = tmp + '%s' % _list[i]
            else:
                tmp = tmp + '%s' % _list[i]

        if i < len(_list)-1:
            tmp += ','

    return tmp
