# vim:set sw=4 ts=4 et:

import dateutil
from texttable import Texttable
import cli
import rax.api

class LoadBalancer(object):
    class NotFound(rax.api.Error):
        pass

    def __init__(self, ctx, id):
        self.id = id
        self.ctx = ctx
        self.svc = ctx.service('cloudLoadBalancers')
        self.fetch()

    @staticmethod
    def by_id(ctx, id):
        return LoadBalancer(ctx, id)

    @staticmethod
    def by_name(ctx, name):
        svc = ctx.service('cloudLoadBalancers')
        r = svc.get("loadbalancers")
        j = r.json()

        for l in j['loadBalancers']:
            if l['name'] == name:
                return LoadBalancer(ctx, l['id'])

        raise rax.api.Error('Load balancer "{}" not found'.format(name))
        
    def fetch(self):
        r = self.svc.get("loadbalancers/{}".format(self.id))
        self.details = r.json()['loadBalancer']

    @property
    def name(self):
        return self.details['name']

    @property
    def protocol(self):
        return self.details['protocol']

    @property
    def port(self):
        return self.details['port']

    @property
    def algorithm(self):
        return self.details['algorithm']

    @property
    def status(self):
        return self.details['status']

    @property
    def timeout(self):
        return self.details['timeout']

    @property
    def connection_logging_enabled(self):
        try:
            return self.details['connection_logging']['enabled']
        except KeyError:
            return False

    @property
    def cluster(self):
        return self.details['cluster']['name']

    @property
    def created(self):
        return dateutil.parser.parse(self.details['created']['time'])

    @property
    def updated(self):
        return dateutil.parser.parse(self.details['updated']['time'])

    @property
    def session_persistence_type(self):
        try:
            return self.details['sessionPersistence']['persistenceType']
        except KeyError:
            return None

    class VirtualIP(object):
        def __init__(self, json):
            self.json = json

        def __str__(self):
            return self.address

        __unicode__ = __str__
        __repr__ = __str__

        @property
        def id(self):
            return self.json['id']

        @property
        def address(self):
            return self.json['address']

        @property
        def type(self):
            return self.json['type']

        @property
        def ip_version(self):
            if self.json['ipVersion'] == 'IPV4':
                return 4
            elif self.json['ipVersion'] == 'IPV6':
                return 6
            else:
                return None

    @property
    def virtual_ips(self):
        return [ LoadBalancer.VirtualIP(json) for json in self.details['virtualIps'] ]

    class Node(object):
        def __init__(self, json):
            self.json = json

        def __str__(self):
            return "{}:{}".format(self.address, self.port)

        @property
        def address(self):
            return self.json['address']

        @property
        def port(self):
            return self.json['port']

        @property
        def condition(self):
            return self.json['condition']

        @property
        def status(self):
            return self.json['status']

    @property
    def nodes(self):
        return [ LoadBalancer.Node(json) for json in self.details['nodes'] ]

    class SSLConfiguration(object):
        def __init__(self, json):
            self.json = json

        @property
        def enabled(self):
            return self.json['enabled']

        @property
        def port(self):
            return self.json['securePort'] if self.enabled else None

        @property
        def secure_only(self):
            return True if self.enabled and self.json['secureTrafficOnly'] else False

    @property
    def ssl(self):
        r = self.svc.get("loadbalancers/{}/ssltermination".format(self.id))
        return LoadBalancer.SSLConfiguration(r.json()['sslTermination'])

    class SSLMapping(object):
        def __init__(self, lb, json):
            self.lb = lb
            self.json = json

        @property
        def id(self):
            return self.json['id']

        @property
        def hostname(self):
            return self.json['hostName']

        def delete(self):
            self.lb.svc.delete("loadbalancers/{}/ssltermination/certificatemappings/{}".format(self.lb.id, self.id))

    @property
    def ssl_mappings(self):
        r = self.svc.get("loadbalancers/{}/ssltermination/certificatemappings".format(self.id))
        return [ LoadBalancer.SSLMapping(self, m['certificateMapping']) for m in r.json()['certificateMappings'] ]

    def add_ssl_mapping(self, hostname, key, cert, chain):
        r = self.svc.post(
            "loadbalancers/{}/ssltermination/certificatemappings".format(self.id),
            {
                'certificateMapping': {
                    'hostName': hostname,
                    'privateKey': key,
                    'certificate': cert,
                    'intermediateCertificate': chain,
                }
            })

