# vim:set sw=4 ts=4 et:

from texttable import Texttable
from cli import CLIError

def get_lb_id(ctx, name):
    svc = ctx.service('cloudLoadBalancers')
    r = svc.get("loadbalancers")
    j = r.json()
    lb_id = -1

    for l in j['loadBalancers']:
        if l['name'] == name:
            return l['id']

    raise CLIError('Load balancer "{}" not found'.format(name))

def get_lb(ctx, name):
    svc = ctx.service('cloudLoadBalancers')
    lb_id = get_lb_id(ctx, name)
    r = svc.get("loadbalancers/{}".format(lb_id))
    j = r.json()
    lb = j['loadBalancer']
    return lb

def c_show(ctx, args):
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

def c_show_lb(ctx, args):
    lb = get_lb(ctx, args[0])

    try:
        if lb['connectionLogging']['enabled']:
            connection_logging = 'ON'
        else:
            connection_logging = 'OFF'
    except KeyError:
        connection_logging = 'OFF'

    try:
        session_persistence = lb['sessionPersistence']['persistenceType']
    except KeyError:
        session_persistence = 'OFF'

    t = Texttable()
    t.add_rows([
        [ 'Name',           lb['name'] ],
        [ 'Protocol',       lb['protocol'] ],
        [ 'Port',           lb['port'] ],
        [ 'Algorithm',      lb['algorithm'] ],
        [ 'Status',         lb['status'] ],
        [ 'Timeout',        "{} seconds".format(lb['timeout']) ],
        [ 'Logging',        connection_logging ],
        [ 'IP addresses',   "\n".join([ v['address'] for v in lb['virtualIps'] ]) ],
        [ 'Nodes',          "\n".join([ "{}:{} ({}, {})".format(n['address'], n['port'], n['condition'], n['status']) for n in lb['nodes'] ]) ],
        [ 'Session persistence',    session_persistence ],
        [ 'Cluster',        lb['cluster']['name'] ],
        [ 'Created',        lb['created']['time'] ],
        [ 'Updated',        lb['updated']['time'] ],
    ], False)
    print t.draw()

def c_show_lb_nodes(ctx, args):
    lb = get_lb(ctx, args[0])
    print "\n".join([ "{}:{}".format(n['address'], n['port']) for n in lb['nodes'] ])

def c_show_lb_node(ctx, args):
    lb = get_lb(ctx, args[0])
    for n in lb['nodes']:
        name = "{}:{}".format(n['address'], n['port'])
        if name == args[1]:
            print "{}:".format(name)
            print "    Condition: {}".format(n['condition'])
            print "       Status: {}".format(n['status'])
            return
    
    raise CLIError("Load balancer node {} not found".format(args[1]))

def c_show_lb_protocol(ctx, args):
    lb = get_lb(ctx, args[0])
    print lb['protocol']

def c_show_lb_port(ctx, args):
    lb = get_lb(ctx, args[0])
    print lb['port']

def c_show_lb_algorithm(ctx, args):
    lb = get_lb(ctx, args[0])
    print lb['algorithm']

def c_show_lb_cluster(ctx, args):
    lb = get_lb(ctx, args[0])
    print lb['cluster']

def c_show_lb_addresses(ctx, args):
    lb = get_lb(ctx, args[0])
    print "\n".join([ v['address'] for v in lb['virtualIps'] ])

def c_show_lb_ssl(ctx, args):
    svc = ctx.service('cloudLoadBalancers')
    lb_id = get_lb_id(ctx, args[0])
    r = svc.get("loadbalancers/{}/ssltermination".format(lb_id))

    t = Texttable()
    if r.status_code == 404:
        t.add_rows([
            [ 'Enabled',                'OFF' ],
        ], False)
    else:
        j = r.json()
        s = j['sslTermination']

        if s['enabled']:
            t.add_rows([
                [ 'Enabled',                'ON' ],
                [ 'Port',                   s['securePort'] ],
                [ 'Secure traffic only',    'ON' if s['secureTrafficOnly'] else 'OFF' ],
            ], False)
        else:
            t.add_rows([
                [ 'Enabled',                'OFF' ],
            ], False)

    print t.draw()

def c_show_lb_ssl_certs(ctx, args):
    svc = ctx.service('cloudLoadBalancers')
    lb_id = get_lb_id(ctx, args[0])
    r = svc.get("loadbalancers/{}/ssltermination/certificatemappings".format(lb_id))
    j = r.json()
    cm = j['certificateMappings']
    print "\n".join([ m['certificateMapping']['hostName'] for m in cm ])

def c_lb_no_ssl_map(ctx, args):
    svc = ctx.service('cloudLoadBalancers')
    lb_id = get_lb_id(ctx, args[0])
    r = svc.get("loadbalancers/{}/ssltermination/certificatemappings".format(lb_id))
    j = r.json()
    cm = j['certificateMappings']

    cm_id = -1
    for c in cm:
        if c['certificateMapping']['hostName'] == args[1]:
            cm_id = c['certificateMapping']['id']
    if cm_id == -1:
        raise CLIError("Certificate mapping for <{}> on <{}> not found".format(args[1], args[0]))
    r = svc.delete("loadbalancers/{}/ssltermination/certificatemappings/{}".format(lb_id, cm_id))

    if 'message' in j:
        print(j['message'])

def c_lb_ssl_map(ctx, args):
    svc = ctx.service('cloudLoadBalancers')
    lb_id = get_lb_id(ctx, args[0])

    host = args[1]

    try:
        with open(args[2], 'r') as fh:
            key = '\n'.join(fh.readlines())
    except:
        raise CLIError("Key file <{}> not found".format(args[2]))

    try:
        with open(args[3], 'r') as fh:
            cert = '\n'.join(fh.readlines())
    except:
        raise CLIError("Certificate file <{}> not found".format(args[3]))

    try:
        with open(args[4], 'r') as fh:
            chain = '\n'.join(fh.readlines())
    except:
        raise CLIError("Certificate file <{}> not found".format(args[4]))

    r = svc.post(
        "loadbalancers/{}/ssltermination/certificatemappings".format(lb_id),
        {
            'certificateMapping': {
                'hostName': host,
                'privateKey': key,
                'certificate': cert,
                'intermediateCertificate': chain,
            }
        })

    j = r.json()
    if 'message' in j:
        print(j['message'])

commands = [
    [ 'show lb', c_show ],
    [ 'show lb <name>', c_show_lb ],
    [ 'show lb <name> ssl', c_show_lb_ssl ],
    [ 'show lb <name> node', c_show_lb_nodes ],
    [ 'show lb <name> node <addr>', c_show_lb_node ],
    [ 'show lb <name> protocol', c_show_lb_protocol ],
    [ 'show lb <name> port', c_show_lb_port ],
    [ 'show lb <name> algorithm', c_show_lb_algorithm ],
    [ 'show lb <name> cluster', c_show_lb_cluster ],
    [ 'show lb <name> addresses', c_show_lb_addresses ],
    [ 'show lb <name> ssl maps', c_show_lb_ssl_certs ],
    [ 'lb <name> ssl map host <host> key <keyfile> certificate <certfile> chain <chainfile>', c_lb_ssl_map ], 
    [ 'no lb <name> ssl map host <host>', c_lb_no_ssl_map ],
]
