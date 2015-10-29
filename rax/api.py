# vim:sw=4 ts=4 et:

import dateutil.parser, pytz, datetime, os, requests, logging, json, warnings
IDENTITY_ENDPOINT = 'https://identity.api.rackspacecloud.com/v2.0/'

#import httplib as http_client
#http_client.HTTPConnection.debuglevel = 1
#logging.basicConfig() 
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True

class Error(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

class LoginError(Error):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "Login error: {}".format(self.value)

class Service(object):
    def __init__(self, ctx, url):
        self.ctx = ctx
        self.url = url

    def post(self, url, data={}):
        return self.ctx.post("{}/{}".format(self.url, url), data)

    def get(self, url, data = {}):
        return self.ctx.get("{}/{}".format(self.url, url, data))

    def delete(self, url):
        return self.ctx.delete("{}/{}".format(self.url, url))

    def put(self, url, data={}):
        return self.ctx.put("{}/{}".format(self.url, url), data)

class Context(object):
    def __init__(self, account='default'):
        self.account = account
        self.datadir = "{}/.raxtool".format(os.path.expanduser("~"))
        self.datafile = "{}/{}.json".format(self.datadir, account)

        if not os.path.isdir(self.datadir):
            os.makedirs(self.datadir)

        try:
            with open(self.datafile, 'r') as fh:
                self.account_data = json.load(fh)
        except Exception, e:
            self.account_data = {}

    def save_account(self):
        with open(self.datafile, 'w') as fh:
            json.dump(self.account_data, fh)

    def logout(self):
        try:
            os.remove(self.datafile)
        except OSError:
            pass

    def get_token(self):
        try:
            return self.account_data['token']['id']
        except KeyError:
            return None

    def get(self, url, data = {}):
        token = self.get_token()
        headers = {
            'Accept': 'application/json',
        }
        if token != None:
            headers['X-Auth-Token'] = token

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = requests.get(url, data, headers = headers)
            return r

    def delete(self, url):
        token = self.get_token()
        headers = {
            'Accept': 'application/json',
        }
        if token != None:
            headers['X-Auth-Token'] = token

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = requests.delete(url, headers = headers)
            return r

    def put(self, url, data):
        token = self.get_token()
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        if token != None:
            headers['X-Auth-Token'] = token

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = requests.put(url, json.dumps(data), headers = headers)
            return r

    def post(self, url, data):
        token = self.get_token()
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        if token != None:
            headers['X-Auth-Token'] = token

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = requests.post(url, json.dumps(data), headers = headers)
            return r

    def check_token(self):
        if 'token' not in self.account_data:
            return False
        token_expire = dateutil.parser.parse(self.account_data['token']['expires'])
        now = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
        if token_expire <= now:
            return False
        return True

    def get_endpoint_url(self, endpoint):
        for service in self.account_data['service_catalog']:
            if service['name'] == endpoint:
                for ep in service['endpoints']:
                    if ep['region'] == self.account_data['region']:
                        return ep['publicURL']
        return None

    def service(self, sname):
        return Service(self, self.get_endpoint_url(sname))

    def login(self, region, username, apikey):
        r = self.post("{}/tokens".format(IDENTITY_ENDPOINT), {
                "auth": {
                    "RAX-KSKEY:apiKeyCredentials": {
                        "username": username,
                        "apiKey": apikey,
                    }
                }
           })
        j = r.json()

        if 'unauthorized' in j:
            raise LoginError(j['unauthorized']['message'])

        self.account_data['region'] = region
        self.account_data['service_catalog'] = j['access']['serviceCatalog']
        self.account_data['token'] = j['access']['token']
        self.save_account()

        return True

