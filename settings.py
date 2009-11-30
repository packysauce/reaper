# Django settings for reaper project.
import os

DEBUG = True
TEMPLATE_DEBUG = DEBUG
DEBUG_HOST = "tonystark"

if DEBUG:
    SITE_URL = "http://tonystark.jlab.org"
else:
    SITE_URL = "https://jsl8.jlab.org/sarim"

ADMINS = (
    ('Patrick White', 'pdwhite@jlab.org.'),
    # ('Your Name', 'your_email@domain.com'),
)

MANAGERS = ADMINS

DATABASE_ENGINE = 'mysql'           # 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
DATABASE_NAME = 'sarim'             # Or path to database file if using sqlite3.
DATABASE_USER = 'sarimrw'             # Not used with sqlite3.
DATABASE_PASSWORD = 'vs-script,rw'         # Not used with sqlite3.
DATABASE_HOST = 'ccdevdb'             # Set to empty string for localhost. Not used with sqlite3.
DATABASE_PORT = ''             # Set to empty string for default. Not used with sqlite3.

EMAIL_HOST = 'smtpmail.jlab.org'
EMAIL_PORT = '25'

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'America/New_York'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = False

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
if not DEBUG:
    MEDIA_ROOT = '/opt/reaper/sarim/static'
else:
    MEDIA_ROOT = 'C:\\users\\pdwhite\\desktop\\reaper\\common\\static'
PROJECT_ROOT = os.path.realpath(os.path.dirname(__file__))

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
# Examples: "http://media.lawrence.com", "http://example.com/media/"
if not DEBUG:
    MEDIA_URL = 'https://jsl8.jlab.org/sarim/site_media/'
else:
    MEDIA_URL = 'http://' + DEBUG_HOST + '/site_media/'

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
if not DEBUG:
    ADMIN_MEDIA_PREFIX = '/media/'
else:
    ADMIN_MEDIA_PREFIX = 'http://' + DEBUG_HOST + '/admin_media/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'x)a51zz(%*mr=0&jfkrg1u^x=622+1icq#tc-30*%k#b%y*j-j'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.load_template_source',
    'django.template.loaders.app_directories.load_template_source',
#     'django.template.loaders.eggs.load_template_source',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.RemoteUserMiddleware',
)

AUTHENTICATION_BACKENDS = ( 
   'django.contrib.auth.backends.RemoteUserBackend',
)

AUTH_PROFILE_MODULE = 'userprofile.UserProfile'

ROOT_URLCONF = 'reaper.urls'

TEMPLATE_DIRS = (
    os.path.join(PROJECT_ROOT, 'common','templates')
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

INSTALLED_APPS = (
    'django_extensions',
    'django.contrib.databrowse',
    'reaper.common',
    'reaper.devices',
    'reaper.sarim',
    'reaper.vulnerabilities',
    'reaper.plugins',
    'reaper.falsepositives',
    'reaper.scans',
    'reaper.userprofile',
    'reaper.subscriptions',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    #'django.contrib.sites',
)

LOGIN_URL = '/loginrequired'
