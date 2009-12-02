from django.template import Library

register = Library()

@register.filter
def scantype(x):
    return x.scanrun.scanset.type
