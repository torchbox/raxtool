# raxtool

A CLI tool for interacting with Rackspace Cloud API. Before you begin you will need the following:

## Get started

To install the required packages:

```
pip install -r requirements.txtpython raxtool.py
```

The first time you run the command you will be prompted for your username, API key and which datacenter to use (e.g. LON, ORD, DFW).

```
./raxtool.py
Username: username
API key: changeme
Region (e.g. LON): ORD
raxtool>
```

## Examples

Show all loadbalancers:

```
raxtool> show lb
```

Show addresses for load balancer:

```
raxtool>show lb fe-1-dist addresses
```

Show SSL mappings.

```
raxtool> show lb fe-1-dist ssl maps
```
