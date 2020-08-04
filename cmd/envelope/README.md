# Envelope Service

Before a service supports access tokens natively, the envelope service
provides a way to deploy new services while the envelope service accepts
access tokens on its behalf.

The envelope service accepts HTTPS requests with `access_token=` parameters,
validates them, and adds an iptables rule granting the client IP time to run
a measurement before removing the rule again after a timeout.

## Deployment

The envelope service dynamically adds individual IP addresses to the `INPUT`
iptables chain. The `OUTPUT` chain is unmodified to allow outbound
connections and reply packets.

### Docker and Kubernetes

Because the envelope service manipulates the local netfilter rules with
iptables, additional capabilities are required: CAP_NET_ADMIN.

Operations with CAP_NET_ADMIN are restricted to the network namespace of the
process. However, the measurement service behind the envelope service could
potentially set interface promiscuity to sniff traffic from other interfaces.

See also [man7/capabilities][cap].

[cap]: http://man7.org/linux/man-pages/man7/capabilities.7.html

#### Docker

```sh
docker run --rm --cap-add=NET_ADMIN -it example/envelope:v0 bash
```

#### Kubernetes

```yaml
spec:
  containers:
  - name: envelope
    image: example/envelope:v0
    securityContext:
      capabilities:
        add: ['NET_ADMIN']
```

### Initialize iptable Rules

The envelope service expects that the iptable rules implement the default
policy to drop connections other than to the envelope service itself.

For example:

```sh
# Flushing existing rules does not change default policy.
iptables --flush

# Set default policy for INPUT chain to DROP packets. Dropping packets
# guarantees that nothing gets in that should not. The remaining rules
# selectively open access where necessary.
iptables -P INPUT DROP

# Accept traffic from devices connected to private and local networks. This is
# necessary for intra-container communications on loopback and for monitoring
# traffic over the private kubernetes network.
# NOTE: On M-Lab k8s deployments, `net1` is the public facing device.
iptables -A INPUT -i eth0 -p all -j ACCEPT
iptables -A INPUT -i lo -p all -j ACCEPT

# Accept incoming connections to the envelope service HTTPS server.
iptables -A INPUT -p tcp --dport 8880 -j ACCEPT  # Envelop service.
iptables -A INPUT -p udp --dport 53 -j ACCEPT  # DNS
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# The last rule "rejects" packets, to send clients a signal that their
# connection was refused rather than silently dropped.
iptables -A INPUT -j REJECT
```

## Examples

### Issue access token

Ultimately these tokens will be issued by the locate service. For now, the
example-signer can create access tokens for local testing.

```sh
go get github.com/m-lab/access/cmd/example-signer

~/bin/example-signer -private jwk_sig_EdDSA_1 -machine mlab1.lga03 -subject 127.0.0.2
http://localhost:8880/v0/allow?access_token=eyJhbGciOiJFZERTQSIsImtpZCI6IjEifQ.
eyJhdWQiOlsibWxhYjEubGdhMDMiXSwiZXhwIjoxNTg0NTAyMjEyLCJpc3MiOiJsb2NhdGUubWVhc3VyZW1lb
nRsYWIubmV0Iiwic3ViIjoiMTI3LjAuMC4yIn0.FZSjjDjWJVGSKzJKJP5Cbaacp8PNqGX5_zETe3SQsXvhlo
hGlAlKLdhDkjBDIKttXkO3BL5xyQ09cVGfmbelDA
```

### Local development without access tokens

Start the access envelope server, without requiring access tokens (and
without iptables management; by default these are both required).

```sh
~/bin/envelope -envelope.token-required=false
```

Connect to the local access envelope using `curl`. When tokens are not
required, the default timeout is 60s. After this timeout, the server will
hangup automatically.

```sh
curl --no-buffer \
  --header "Connection: Upgrade" \
  --header "Upgrade: websocket" \
  --header "Sec-WebSocket-Protocol: net.measurementlab.envelope" \
  --header "Sec-WebSocket-Version: 13" \
  --header "Sec-WebSocket-Key: aGVsbG8K" \
    http://localhost:8880/v0/envelope/access
```
