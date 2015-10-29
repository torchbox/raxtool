# vim:set sw=4 ts=4 et:

import dateutil
from texttable import Texttable
import cli
import rax.api

def c_show(p, ctx, args):
    svc = ctx.service('cloudLoadBalancers')

    r = svc.get("loadbalancers")
    j = svc.json()
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
    print t.draw()

def c_show_lb(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])

    t = Texttable()
    t.add_rows([
        [ 'Name',                   lb.name ],
        [ 'Protocol',               lb.protocol ],
        [ 'Port',                   lb.port ],
        [ 'Algorithm',              lb.algorithm ],
        [ 'Status',                 lb.status ],
        [ 'Timeout',                "{} seconds".format(lb.timeout) ],
        [ 'Logging',                "ON" if lb.connection_logging_enabled is None else "OFF" ],
        [ 'IP addresses',           "\n".join([ str(v) for v in lb.virtual_ips ]) ],
        [ 'Nodes',                  "\n".join([ "{} ({}, {})".format(n, n.condition, n.status) for n in lb.nodes ]) ],
        [ 'Session persistence',    "OFF" if lb.session_persistence_type is None else lb.session_persistence_type ],
        [ 'Cluster',                lb.cluster ],
        [ 'Created',                lb.created ],
        [ 'Updated',                lb.updated ],
    ], False)
    print t.draw()

def c_show_lb_nodes(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])
    print "\n".join([ str(n) for n in lb.nodes ])

def c_show_lb_node(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])

    for n in lb.nodes:
        if str(n) == args[1]:
            print "{}:".format(n)
            print "    Condition: {}".format(n.condition)
            print "       Status: {}".format(n.status)
            return
    
    raise cli.CLIError("Load balancer node {} not found".format(args[1]))

def c_show_lb_protocol(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])
    print lb.protocol

def c_show_lb_port(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])
    print lb.port

def c_show_lb_algorithm(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])
    print lb.algorithm

def c_show_lb_cluster(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])
    print lb.cluster

def c_show_lb_addresses(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])
    print "\n".join([ str(v) for v in lb.virtual_ips ])

def c_show_lb_ssl(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])
    ssl = lb.ssl

    t = Texttable()
    if ssl.enabled:
        t.add_rows([
            [ 'Enabled',                'ON' ],
            [ 'Port',                   ssl.port ],
            [ 'Secure traffic only',    'ON' if ssl.secure_only else 'OFF' ],
        ], False)
    else:
        t.add_rows([
            [ 'Enabled',                'OFF' ],
        ], False)

    print t.draw()

def c_show_lb_ssl_certs(p, ctx, args):
    lb = LoadBalancer.by_name(ctx, args[0])
    print "\n".join([ m.hostname for m in lb.ssl_mappings ])


class LBSSLMode(cli.Mode):
    def __init__(self, args, lbname):
        super(LBSSLMode, self).__init__('ssl')
        self.lbname = lbname
        self.add_commands([
            [ 'map', None, "Add a new SSL certificate map" ],
            [ 'map host', None, "Certificate domain" ],
            [ 'map host <host>', None, "Certificate domain" ],
            [ 'map host <host> key <keyfile> certificate <certfile> chain <chainfile>', self.c_map ], 
            [ 'no map', None, 'Remove SSL certificate map' ],
            [ 'no map host <host>', self.c_no_map ],
        ])

    def c_map(self, p, ctx, args):
        lb = LoadBalancer.by_name(ctx, self.lbname)
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

        lb.add_ssl_mapping(host, key, cert, chain)

    def c_no_map(self, p, ctx, args):
        lb = LoadBalancer.by_name(ctx, self.lbname)

        mapping = None
        for cm in lb.ssl_mappings:
            if cm.hostname == args[1]:
                mapping = cm
                break

        if mapping is None:
            raise cli.CLIError("Certificate mapping for <{}> on <{}> not found".format(args[1], args[0]))

        mapping.delete()

class LBMode(cli.Mode):
    def __init__(self, args):
        super(LBMode, self).__init__('lb')
        self.lbname = args[0]
        self.add_commands([
            [ 'ssl', cli.set_mode(LBSSLMode, self.lbname), "Configure SSL parameters" ],
        ])

    @property
    def prompt(self):
        return "lb[{}]".format(self.lbname)

commands = [
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
    [ 'lb', None, "Configure Cloud Load Balancer" ],
    [ 'lb <name>', cli.set_mode(LBMode), "Load balancer name" ],
]
