from django.template import Library

register = Library()

@register.filter
def search_width(l):
    if l > 3:
        return 1000
    else:
        return [250,500,750][l-1]

@register.filter
def search_height(l):
    r = l/4*19
    if r == 0:
        r = 25

    return r
