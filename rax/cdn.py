# vim:set sw=4 ts=4 et:

from rax import api

class CDN(object):
    class NotFound(api.Error):
        pass

    def __init__(self, ctx, json):
        print(json)
        self.ctx = ctx
        self.svc = ctx.service('rackCDN')
        self._modified = False
        self.json = json

        if 'id' in json:
            self.id = json['id']
        else:
            self.id = None

    @staticmethod
    def by_name(ctx, name):
        svc = ctx.service('rackCDN')
        r = svc.get("services")
        j = r.json()

        for l in j['services']:
            if l['name'] == name:
                return CDN(ctx, l)

        raise CDN.NotFound('CDN "{}" not found.'.format(name))

    @staticmethod
    def all(ctx):
        svc = ctx.service('rackCDN')
        r = svc.get("services")
        j = r.json()

        return [ CDN(ctx, l) for l in j['services'] ]

    class Flavour(object):
        class Provider(object):
            def __init__(self, flavour, json):
                self.flavour = flavour
                self.json = json
            
            @property
            def name(self):
                return self.json['provider']

            @property
            def url(self):
                for link in self.json['links']:
                    if link['rel'] == 'provider_url':
                        return link['href']
                return None

        def __init__(self, ctx, json):
            self.cdn = ctx
            self.json = json

        @property
        def name(self):
            return self.json['id']

        @property
        def providers(self):
            return [ CDN.Flavour.Provider(self, obj) for obj in self.json['providers'] ]

    @staticmethod
    def flavours(ctx):
        svc = ctx.service('rackCDN')
        r = svc.get('flavors')
        j = r.json()

        return [ CDN.Flavour(ctx, obj) for obj in j['flavors'] ]

    class Domain(object):
        def __init__(self, cdn, json):
            self.cdn = cdn
            self.json = json

        @property
        def domain(self):
            return self.json['domain']

    class Origin(object):
        def __init__(self, cdn, json):
            self.cdn = cdn
            self.json = json

        @property
        def origin(self):
            return self.json['origin']

        @property
        def port(self):
            return self.json['port']

        @property
        def ssl(self):
            return self.json['ssl']

    class Cache(object):
        class Rule(object):
            def __init__(self, cache, json):
                self.cache = cache
                self.json = json

            @property
            def name(self):
                return self.json['name']

            @property
            def request_url(self):
                return self.json['request_url']

        def __init__(self, cdn, json):
            self.cdn = cdn
            self.json = json

        @property 
        def name(self):
            return self.json['name']

        @property
        def ttl(self):
            return self.json['ttl']

        @property
        def rules(self):
            if 'rules' not in self.json:
                return []

            return [ CDN.Cache.Rule(self, json) for json in self.json['rules'] ]

    @property
    def name(self):
        return self.json['name']

    @name.setter
    def name(self, v):
        self._modified = True
        self.json['name'] = v

    @property
    def domains(self):
        return [ CDN.Domain(self, obj) for obj in self.json['domains'] ]

    @property
    def origins(self):
        return [ CDN.Origin(self, obj) for obj in self.json['origins'] ]

    @property
    def caches(self):
        return [ CDN.Cache(self, obj) for obj in self.json['caching'] ]

    @property
    def status(self):
        return self.json['status']

    @property
    def flavour(self):
        return self.json['flavor_id']

    @flavour.setter
    def flavour(self, v):
        self.json['flavor_id'] = v

    @property
    def log_delivery(self):
        try:
            return self.json['log_delivery']
        except KeyError:
            return False

    @log_delivery.setter
    def log_delivery(self, v):
        self._modified = True
        if 'log_delivery' not in self.json:
            self.json['log_delivery'] = {}
        self.json['log_delivery'] = v

    def purge(self, path, hard=False):
        request = {
            'url': path,
            'hard': hard,
        }

        svc = ctx.service('rackCDN')
        r = svc.delete("services/{}/assets".format(self.id), request)

    def save(self):
        if not self._modified:
            return False

        svc = self.ctx.service('rackCDN')
        r = svc.post("services", data = self.json)

        if r.status_code != 202:
            raise api.Error("{}: {}".format(r.reason, r.json()['message']))
