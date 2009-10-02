
class DummyUsernameMiddleware(object):
    lastuser = 'pdwhite'

    def process_request(self, request):
        try:
            request.META["REMOTE_USER"] = request.GET['testuser']
            lastuser = request.GET['testuser']
        except:
            request.META["REMOTE_USER"] = self.lastuser
