# raxtool

A CLI tool for interacting with Rackspace Cloud API. Before you begin you will need the following:

## Get started

To install the required packages:

```
pip install -r requirements.txt
python raxtool.py
```

The first time you run the command you will be prompted for your username, API key and which datacenter to use (e.g. LON, ORD, DFW).

```
./raxtool.py
Username: username
API key: changeme
Region (e.g. LON): ORD
raxtool>
```

You may want to run inside a docker container.

```
docker run -v "`pwd`:/raxtool" -it python:2.7 /bin/sh -c 'cd /raxtool ; pip install -r requirements.txt ; ./raxtool.py'
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

Update an SSL mapping.

```

raxtool> config
raxtool(config)> lb fe-1-dist
raxtool(config-lb)> ssl
raxtool(config-lb-ssl)> map host www.domain.com key www.domain.com.key certificate www.domain.com.crt chain www.domain.com.ca-bundle
```
