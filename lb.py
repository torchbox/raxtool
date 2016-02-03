# vim:set sw=4 ts=4 et:

import dateutil, sys
from OpenSSL import crypto
from functools import partial
from texttable import Texttable
import cli
from rax import api
from rax.lb import LoadBalancer

def c_show(p, ctx, args):
    svc = ctx.service('cloudLoadBalancers')

    r = svc.get("loadbalancers")
    j = r.json()

    t = Texttable()
    t.set_cols_width([ 15, 5, 5, 5, 55 ])
    t.set_cols_align([ 'l', 'r', 'l', 'r', 'l' ])
    t.add_rows([[ 'NAME', 'NODES', 'PROTO', 'PORT', 'IP(S)' ]] + [
        [
            lb['name'], 
            lb['nodeCount'],
            lb['protocol'],
            lb['port'],
            ", ".join([ v['address'] for v in lb['virtualIps'] ]),

        ] for lb in j['loadBalancers']
    ])

    print(t.draw())

def c_no_lb(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)
    lb.delete()

def c_show_lb(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.CLIError(str(e))

    nodes = "\n".join([
        "     {address}:{port} ({condition}, {status})".format(
            address = node.address,
            port = node.port,
            condition = node.condition,
            status = node.status
       ) for node in lb.nodes
    ])

    ips = ", ".join([ str(v) for v in lb.virtual_ips ])
    usage = lb.usage

    print(
"""Load balancer {name}, id {id} on {cluster}
  Protocol {protocol}, port {port}.
  Load balancing algorithm is {algorithm}, timeout = {timeout} seconds.
  Logging {logging}.
  Session persistence {persist}.
  Status: {status}
  IP addresses: {ips}.
  Nodes:
{nodes}
  24 hour input rate {in_bytes:0.0f} bytes/sec, average connections {avg_conn:0.2f}
  24 hour output rate {out_bytes:0.0f} bytes/sec
""".format(
    name = lb.name,
    id = lb.id,
    protocol = lb.protocol,
    port = lb.port,
    cluster = lb.cluster,
    algorithm = lb.algorithm,
    timeout = lb.timeout,
    logging = "enabled" if lb.connection_logging_enabled else "disabled",
    persist = "disabled" if lb.session_persistence_type is None else lb.session_persistence_type,
    status = lb.status,
    nodes = nodes,
    ips = ips,
    created = lb.created,
    updated = lb.updated,
    in_bytes = usage['incoming_bytes_per_second'],
    out_bytes = usage['outgoing_bytes_per_second'],
    avg_conn = usage['average_connections']))

def c_show_lb_nodes(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)
    print("\n".join([ str(n) for n in lb.nodes ]))

def c_show_lb_node(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)

    for n in lb.nodes:
        if str(n) == args[1]:
            print("{}:".format(n))
            print("    Condition: {}".format(n.condition))
            print("       Status: {}".format(n.status))
            return
    
    raise cli.CLIError("Load balancer node {} not found".format(args[1]))

def c_show_lb_protocol(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)
    print(lb.protocol)

def c_show_lb_port(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)
    print(lb.port)

def c_show_lb_algorithm(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)
    print(lb.algorithm)

def c_show_lb_cluster(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)
    print(lb.cluster)

def c_show_lb_addresses(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)
    print("\n".join([ str(v) for v in lb.virtual_ips ]))

def c_show_lb_ssl(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)
    ssl = lb.ssl

    if not ssl.enabled:
        print("SSL not configured.")
        return

    print("SSL enabled, port {}, {}".format(ssl.port, "secure traffic only" if ssl.secure_only else "insecure traffic permitted"))
    print("Certificate: ")

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, ssl.certificate.replace("\n\n", "\n"))

    subject = "".join([ "/{}={}".format(c[0], c[1]) for c in cert.get_subject().get_components() ])
    sys.stdout.write("  Subject: {}\n".format(subject))

    extensions = { cert.get_extension(i).get_short_name(): cert.get_extension(i) for i in range(0, cert.get_extension_count()) }
    if 'subjectAltName' in extensions:
        sys.stdout.write("  Alternative subject names: {}\n".format(extensions['subjectAltName']._subjectAltNameString()))

def c_show_lb_ssl_certs(p, ctx, args):
    try:
        lb = LoadBalancer.by_name(ctx, args[0])
    except api.Error, e:
        raise cli.Error(e)

    for map in lb.ssl_mappings:
        r = lb.svc.get("loadbalancers/{}/ssltermination/certificatemappings/{}".format(lb.id, map.id))

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, r.json()['certificateMapping']['certificate'].replace("\n\n", "\n"))

        sys.stdout.write("{}:\n".format(map.hostname))
        subject = "".join([ "/{}={}".format(c[0], c[1]) for c in cert.get_subject().get_components() ])
        sys.stdout.write("  Subject: {}\n".format(subject))

        extensions = { cert.get_extension(i).get_short_name(): cert.get_extension(i) for i in range(0, cert.get_extension_count()) }
        if 'subjectAltName' in extensions:
            sys.stdout.write("  Alternative subject names: {}\n".format(extensions['subjectAltName']._subjectAltNameString()))

class LBNodeMode(cli.Mode):
    def __init__(self, ctx, args, lb):
        super(LBNodeMode, self).__init__('node')

        bits = args[0].split(':')
        if len(bits) != 2:
            raise cli.CLIError("Node name should be in the form address:port")

        self.lb = lb
        self.node = None

        for node in self.lb.nodes:
            if "{}:{}".format(node.address, node.port) == args[0]:
                self.node = node
                break

        if self.node is None:
            sys.stdout.write("% Creating new node.\n")
            self.node = LoadBalancer.Node(self.lb, {
                'address': bits[0],
                'port': bits[1],
                'condition': LoadBalancer.Node.CONDITION_ENABLED,
                'type': LoadBalancer.Node.TYPE_PRIMARY,
            })

        self.add_commands([
            [ 'enable', self.c_disable, 'Enable node' ],
            [ 'disable', self.c_disable, 'Disable node' ],
            [ 'drain', self.c_drain, 'Drain node' ],
            [ 'primary', self.c_primary, 'Make node primary' ],
            [ 'secondary', self.c_secondary, 'Make node secondary' ],
            [ 'commit', self.c_commit, 'Commit pending changes' ],
        ])

    def c_disable(self, p, ctx, args):
        self.node.condition = LoadBalancer.Node.CONDITION_DISABLED

    def c_enable(self, p, ctx, args):
        self.node.condition = LoadBalancer.Node.CONDITION_ENABLED

    def c_drain(self, p, ctx, args):
        self.node.condition = LoadBalancer.Node.CONDITION_DRAINING

    def c_primary(self, p, ctx, args):
        self.node.type = LoadBalancer.Node.TYPE_PRIMARY

    def c_secondary(self, p, ctx, args):
        self.node.type = LoadBalancer.Node.TYPE_SECONDARY

    def c_commit(self, parser, ctx, args):
        try:
            self.node.save()
        except api.Error, e:
            raise cli.CLIError(str(e))

class LBSSLMode(cli.Mode):
    def __init__(self, ctx, args, lb):
        super(LBSSLMode, self).__init__('ssl')
        self.lb = lb
        self.add_commands([
            [ 'map', None, "Add a new SSL certificate map" ],
            [ 'map host', None, "Certificate domain" ],
            [ 'map host <host>', None, "Certificate domain" ],
            [ 'map host <host> key <keyfile> certificate <certfile> chain <chainfile>', self.c_map ], 
            [ 'no map', None, 'Remove SSL certificate map' ],
            [ 'no map host <host>', self.c_no_map ],
        ])

    def c_map(self, p, ctx, args):
        host = args[0]

        try:
            with open(args[1], 'r') as fh:
                key = '\n'.join(fh.readlines())
        except:
            raise cli.CLIError("Key file <{}> not found".format(args[2]))

        try:
            with open(args[2], 'r') as fh:
                cert = '\n'.join(fh.readlines())
        except:
            raise cli.CLIError("Certificate file <{}> not found".format(args[3]))

        try:
            with open(args[3], 'r') as fh:
                chain = '\n'.join(fh.readlines())
        except:
            raise cli.CLIError("Certificate file <{}> not found".format(args[4]))

        # Do we already have a mapping for this hostname?
        mapping = None
        for cm in self.lb.ssl_mappings:
            if cm.hostname == host:
                mapping = cm
                break

        if mapping is None:
            print('% Creating new mapping for "{}".'.format(host))
            self.lb.add_ssl_mapping(host, key, cert, chain)
        else:
            print('% Replacing existing mapping for "{}".'.format(host))
            mapping.update(key, cert, chain)

    def c_no_map(self, p, ctx, args):
        mapping = None
        for cm in self.lb.ssl_mappings:
            if cm.hostname == args[0]:
                mapping = cm
                break

        if mapping is None:
            raise cli.CLIError("Certificate mapping for <{}> on <{}> not found".format(args[1], args[0]))

        mapping.delete()

class LBMode(cli.Mode):
    def __init__(self, ctx, args):
        super(LBMode, self).__init__('lb')

        self.lbname = args[0]

        try:
            self.lb = LoadBalancer.by_name(ctx, self.lbname)
            if self.lb.status in ['BUILD', 'PENDING_UPDATE', 'PENDING_DELETE', 'DELETED']:
                raise cli.CLIError("Cannot configure a load balancer in {} state".format(self.lb.status))
        except LoadBalancer.NotFound:
            self.lb = LoadBalancer(ctx, None)
            self.lb.name = self.lbname
            sys.stdout.write("% Creating new load balancer.\n")
            self.add_commands([
                [ 'ip-type', None, 'Set incoming IP address type' ],
                [ 'ip-type public', self.c_ip_type_public, 'Public Internet IP address' ],
                [ 'ip-type servicenet', self.c_ip_type_servicenet, 'Rackspace ServiceNet IP address' ],
            ])

        self.add_commands([
            [ 'port', None, 'Incoming port' ],
            [ 'port <port>', self.c_port ],
            [ 'protocol', None, 'Incoming protocol' ],
            [ 'protocol <protocol>', self.c_protocol ],
            [ 'half-closed', self.c_half_closed, 'Enable half-closed connection support' ],
            [ 'ssl', cli.set_mode(LBSSLMode, self.lb), "Configure SSL parameters" ],
            [ 'node', None,  "Configure origin nodes" ],
            [ 'node <address:port>', cli.set_mode(LBNodeMode, self.lb) ],
            [ 'algorithm', None, 'Select load balancing algorithm' ],
            [ 'algorithm least-connections', 
                partial(self.c_algorithm, LoadBalancer.ALGORITHM_LEAST_CONNECTIONS),
                "Route requests to node with fewest connections" ],
            [ 'algorithm random',
                partial(self.c_algorithm, LoadBalancer.ALGORITHM_RANDOM), 
                'Select node at random' ],
            [ 'algorithm round-robin',
                partial(self.c_algorithm, LoadBalancer.ALGORITHM_ROUND_ROBIN),
                'Use each node in turn' ],
            [ 'algorithm weighted-least-connections', 
                partial(self.c_algorithm, LoadBalancer.ALGORITHM_WEIGHTED_LEAST_CONNECTIONS),
                "As least-connections, but with node weight considered"],
            [ 'algorithm weighted-round-robin',
                partial(self.c_algorithm, LoadBalancer.ALGORITHM_WEIGHTED_ROUND_ROBIN),
                "As round-robin, but with node weight considered"],
            [ 'no', None, 'Remove or negate configuration options' ],
            [ 'no half-closed', self.c_no_half_closed, 'Disable half-closed connection support ' ],
            [ 'no node', None, 'Remove a node' ],
            [ 'no node <address:port>', self.c_no_node ],
            [ 'commit', self.c_commit, 'Commit pending changes' ],
        ])

    def c_no_node(self, parser, ctx, args):
        for node in self.lb.nodes:
            if "{}:{}".format(node.address, node.port) == args[0]:
                node.delete()
                return
        raise cli.CLIError("Node not configured.")

    def c_ip_type_public(self, parser, ctx, args):
        self.lb._ip_type = LoadBalancer.IP_TYPE_PUBLIC

    def c_ip_type_servicenet(self, parser, ctx, args):
        self.lb._ip_type = LoadBalancer.IP_TYPE_SERVICENET

    def c_algorithm(self, algorithm, parser, ctx, args):
        self.lb.algorithm = algorithm

    def c_port(self, parser, ctx, args):
        self.lb.port = args[0]

    def c_protocol(self, parser, ctx, args):
        self.lb.protocol = args[0]

    def c_half_closed(self, parser, ctx, args):
        self.lb.half_closed = True

    def c_no_half_closed(self, parser, ctx, args):
        self.lb.half_closed = False

    def c_commit(self, parser, ctx, args):
        if self.lb.port == None:
            raise cli.CLIError("Port must be configured for a new load balancer.")
        if self.lb.protocol == None:
            raise cli.CLIError("Protocol must be configured for a new load balancer.")
        
        try:
            self.lb.save()
        except api.Error, e:
            raise cli.CLIError(str(e))

global_commands = [
    [ 'show lb', c_show, "Cloud Load Balancer" ],
    [ 'show lb <name>', c_show_lb, "Load balancer name" ],
    [ 'show lb <name> ssl', c_show_lb_ssl, "SSL termination configuration" ],
    [ 'show lb <name> node', c_show_lb_nodes, "Node configuration and status" ],
    [ 'show lb <name> node <node>', c_show_lb_node, "Node addr:port" ],
    [ 'show lb <name> protocol', c_show_lb_protocol, "Protocol" ],
    [ 'show lb <name> port', c_show_lb_port, "Port" ],
    [ 'show lb <name> algorithm', c_show_lb_algorithm, "Balancing algorithm" ],
    [ 'show lb <name> cluster', c_show_lb_cluster, "Rackspace cluster name" ],
    [ 'show lb <name> addresses', c_show_lb_addresses, "Incoming IP addresses" ],
    [ 'show lb <name> ssl maps', c_show_lb_ssl_certs, "SSL certificate maps" ],
]

config_commands = [
    [ 'lb', None, "Configure Cloud Load Balancer" ],
    [ 'lb <name>', cli.set_mode(LBMode), "Load balancer name" ],
    [ 'no lb', None, 'Remove load balancer' ],
    [ 'no lb <name>', c_no_lb ],
]
