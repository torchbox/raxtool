# vim:set sw=4 ts=4 et:

import sys
from rax import api
from rax.cdn import CDN
import cli

def c_show(p, ctx, args):
    cdns = CDN.all(ctx)

    for c in cdns:
        print(c.name)

def c_show_cdn(p, ctx, args):
    try:
        c = CDN.by_name(ctx, args[0])
    except CDN.NotFound, e:
        raise cli.CLIError(str(e))

    print("CDN {}, flavour \"{}\":".format(c.name, c.flavour))
    print("  Status: {}".format(c.status))

    print("  Domains:")
    for d in c.domains:
        print("    {}".format(d.domain))

    print("  Origins:")
    for o in c.origins:
        print("    {}://{}:{}".format(
            "https" if o.ssl else "http",
            o.origin,
            o.port))

    caches = c.caches

    for cache in caches:
        if cache.name == 'default':
            print("  Default cache TTL: {}".format(cache.ttl))
            break

    for cache in caches:
        if cache.name == 'default':
            continue

        print("")
        print("  Cache rule {}:".format(cache.name))
        print("    Default TTL {}".format(cache.ttl))
        for rule in cache.rules:
            print("    Match request path {}".format(rule.request_url))

def c_purge(p, ctx, args, hard=False):
    try:
        c = CDN.by_name(ctx, args[0])
    except CDN.NotFound, e:
        raise cli.CLIError(str(e))

def c_purge_hard(p, ctx, args):
    return c_purge(p, ctx, args, hard=True)

def c_show_cdn_flavours(p, ctx, args):
    flavours = CDN.flavours(ctx)

    for flavour in flavours:
        print("\"{}\", providers:".format(flavour.name))
        for provider in flavour.providers:
            if provider.url != None:
                url = ", " + provider.url
            else:
                url = ""
            print("  {}{}".format(provider.name, url))

class CDNMode(cli.Mode):
    def __init__(self, ctx, args):
        super(CDNMode, self).__init__('cdn')

        self.cdnname = args[0]

        try:
            self.cdn = CDN.by_name(ctx, self.cdnname)
        except CDN.NotFound:
            self.cdn = CDN(ctx, {
                'name': self.cdnname,
                'flavor_id': 'cdn',
                'origins': [],
                'domains': []
            })
            self.cdn._modified = True
            sys.stdout.write("% Creating new CDN.\n")

        self.add_commands([
            [ "name", None, "Set CDN name" ],
            [ "name <name>", self.c_name ],
            [ "flavour", None, "Set CDN flavour" ],
            [ "flavour <name>", self.c_flavour ],
            [ "log-delivery", self.c_enable_log_delivery, "Enable log delivery" ],
            [ "no log-delivery", self.c_disable_log_delivery, "Disable log delivery" ],
            [ "commit", self.c_commit, "Commit changes" ],
        ])

    def c_enable_log_delivery(self, parser, ctx, args):
        self.cdn.log_delivery = True

    def c_disable_log_delivery(self, parser, ctx, args):
        self.cdn.log_delivery = False

    def c_flavour(self, parser, ctx, args):
        self.cdn.flavour = args[0]

    def c_name(self, parser, ctx, args):
        self.cdn.name = args[0]

    def c_commit(self, parser, ctx, args):
        try:
            self.cdn.save()
        except api.Error, e:
            raise cli.CLIError(str(e))

global_commands = [
    [ 'show cdn', c_show, 'Show CDN configuration and status' ],
    [ 'show cdn <name>', c_show_cdn, ],
    [ 'show cdn flavours', c_show_cdn_flavours, 'Show available CDN flavours' ],
    [ 'cdn', None, 'Manage Content Delivery Networks' ],
    [ 'cdn purge', None, 'Remove an item from a CDN cache' ],
    [ 'cdn purge <name>', None, 'CDN name' ],
    [ 'cdn purge <name> <path>', c_purge, 'Object path' ],
    [ 'cdn purge <name> <path> hard', c_purge_hard, 'Delete object instead of invalidating' ],
]

config_commands = [
    [ 'cdn', None, "Configure Content Delivery Network" ],
    [ 'cdn <name>', cli.set_mode(CDNMode), "CDN name" ],
    [ 'no cdn', None, 'Remove CDN' ],
#    [ 'no cdn <name>', c_no_cdn ],
]
