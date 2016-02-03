# vim:set sw=4 ts=4 et:

import dateutil, datetime, pytz
from functools import partial
from copy import copy
from texttable import Texttable
import cli
from rax import api

class LoadBalancer(object):
    IP_TYPE_PUBLIC = 0
    IP_TYPE_SERVICENET = 1

    ALGORITHM_ROUND_ROBIN = 'ROUND_ROBIN'
    ALGORITHM_WEIGHTED_ROUND_ROBIN = 'WEIGHTED_ROUND_ROBIN'
    ALGORITHM_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
    ALGORITHM_WEIGHTED_LEAST_CONNECTIONS = 'WEIGHTED_LEAST_CONNECTIONS'
    ALGORITHM_RANDOM = 'RANDOM'

    class NotFound(api.Error):
        def __init__(self, value):
            self.value = value

        def __str__(self):
            return self.value
        __repr__ = __str__
        __unicode__ = __str__

    def __init__(self, ctx, id):
        self.id = id
        self.ctx = ctx
        self.svc = ctx.service('cloudLoadBalancers')
        self._modified = False

        if id is not None:
            self.fetch()
        else:
            self.details = {
                'port': '80',
                'protocol': 'HTTP',
            }
            self._ip_type = LoadBalancer.IP_TYPE_PUBLIC

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

        raise LoadBalancer.NotFound('Load balancer "{}" not found'.format(name))
        
    def delete(self):
        svc = self.ctx.service('cloudLoadBalancers')
        r = svc.delete("loadbalancers/{}".format(self.id))
        if r.status_code != 202:
            raise api.Error("{}: {}".format(r.reason, r.json()['message']))

    def save(self):
        if not self._modified:
            return

        svc = self.ctx.service('cloudLoadBalancers')
        if self.id is None:
            details = copy(self.details)
            details['virtualIps'] = [
                {
                    'type': 'PUBLIC',
                }
            ]
            r = svc.post("loadbalancers", { 'loadBalancer': details })
        else:
            details = {
                'name': self.details['name'],
                'protocol': self.details['protocol'],
                'halfClosed': self.details['halfClosed'],
                'algorithm': self.details['algorithm'],
                'port': self.details['port'],
                'timeout': self.details['timeout'],
            }
            r = svc.put("loadbalancers/{}".format(self.id), { 'loadBalancer': details })

        if r.status_code != 202:
            raise api.Error("{}: {}".format(r.reason, r.json()['message']))

    def fetch(self):
        r = self.svc.get("loadbalancers/{}".format(self.id))
        self.details = r.json()['loadBalancer']

    @property
    def modified(self):
        return self._modified

    @property
    def half_closed(self):
        try:
            return self.details['halfClosed']
        except KeyError:
            return False

    @half_closed.setter
    def half_closed(self, v):
        self.details['halfClosed'] = v
        self._modified = True

    @property
    def name(self):
        try:
            return self.details['name']
        except KeyError:
            return None

    @name.setter
    def name(self, v):
        if v == self.name:
            return
        self.details['name'] = v
        self._modified = True

    @property
    def protocol(self):
        try:
            return self.details['protocol']
        except KeyError:
            return None

    @protocol.setter
    def protocol(self, v):
        self.details['protocol'] = v
        self._modified = True

    @property
    def port(self):
        try:
            return self.details['port']
        except KeyError:
            return None

    @port.setter
    def port(self, v):
        self.details['port'] = v
        self._modified = True

    @property
    def algorithm(self):
        return self.details['algorithm']

    @algorithm.setter
    def algorithm(self, v):
        self.details['algorithm'] = v
        self._modified = True

    @property
    def status(self):
        return self.details['status']

    @property
    def timeout(self):
        return self.details['timeout']

    @timeout.setter
    def timeout(self, v):
        self.details['timeout'] = v
        self._modified = True

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
        TYPE_PRIMARY = 'PRIMARY'
        TYPE_SECONDARY = 'SECONDARY'
        CONDITION_ENABLED = 'ENABLED'
        CONDITION_DRAINING = 'DRAINING'
        CONDITION_DISABLED = 'DISABLED'

        def __init__(self, lb, json = {}):
            self.lb = lb
            self.json = json

            if 'id' not in json:
                self._modified = True
            else:
                self._modified = False

        def __str__(self):
            return "{}:{}".format(self.address, self.port)

        @property
        def id(self):
            try:
                return self.json['id']
            except KeyError:
                return None

        @property
        def address(self):
            return self.json['address']

        @property
        def port(self):
            return self.json['port']

        @property
        def condition(self):
            return self.json['condition']

        @condition.setter
        def condition(self, v):
            self.json['condition'] = v
            self._modified = True

        @property
        def status(self):
            return self.json['status']

        @property
        def type(self):
            return self.json['type']

        @type.setter
        def type(self, v):
            self.json['type'] = v
            self._modified = True

        def save(self):
            if not self._modified:
                return

            svc = self.lb.ctx.service('cloudLoadBalancers')
            details = copy(self.json)

            try:
                del details['status']
                del details['id']
            except KeyError:
                pass

            if self.id is None:
                r = svc.post("loadbalancers/{}/nodes".format(self.lb.id), { 'nodes': [ details ] })
            else:
                del details['address']
                del details['port']
                r = svc.put("loadbalancers/{}/nodes/{}".format(self.lb.id, self.id), { 'node': details })

        def delete(self):
            svc = self.lb.ctx.service('cloudLoadBalancers')
            svc.delete("loadbalancers/{}/nodes/{}".format(self.lb.id, self.id))

    @property
    def nodes(self):
        try:
            return [ LoadBalancer.Node(self, json) for json in self.details['nodes'] ]
        except KeyError:
            return []

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
        def certificate(self):
            return self.json['certificate']

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

        @property
        def certificate(self):
            return self.json['certificate']

        def delete(self):
            self.lb.svc.delete("loadbalancers/{}/ssltermination/certificatemappings/{}".format(self.lb.id, self.id))

        def update(self, key, cert, chain):
            self.lb.svc.put(
                "loadbalancers/{}/ssltermination/certificatemappings/{}".format(self.lb.id, self.id),
                {
                    'certificateMapping': {
                        'hostName': self.hostname,
                        'privateKey': key,
                        'certificate': cert,
                        'intermediateCertificate': chain,
                    }
                })

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

    @property
    def usage(self):
        now = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)

        r = self.svc.get("loadbalancers/{}/usage/current".format(self.id))

        data = r.json()['loadBalancerUsageRecords']
        start_time = None
        end_time = None
        for r in data:
            s = dateutil.parser.parse(r['startTime'])
            if start_time is None or start_time > s:
                start_time = s
        for r in data:
            s = dateutil.parser.parse(r['endTime'])
            if end_time is None or end_time < s:
                end_time = s

        timediff = end_time - start_time

        return {
            'average_connections':
                sum([ c['averageNumConnections'] + c['averageNumConnectionsSsl'] for c in data ]) / len(data),
            'incoming_bytes_per_second': 
                sum([ c['incomingTransfer'] + c['incomingTransferSsl'] for c in data]) / timediff.total_seconds(),
            'outgoing_bytes_per_second': 
                sum([ c['outgoingTransfer'] + c['outgoingTransferSsl'] for c in data]) / timediff.total_seconds(),
        }
