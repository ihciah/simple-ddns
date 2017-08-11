#!/usr/bin/python
# -*- coding: utf-8 -*-
# __author__ = "ihciah"

from twisted.web import resource
from twisted.web import server as webserver
from twisted.internet import reactor, defer
from twisted.names import dns, error, server
from OpenSSL.SSL import Context, TLSv1_METHOD
import hmac, base64, struct, hashlib, time
from site_config import DOMAIN_CONFIG, SERVER_CONFIG


class Auth:
    class OTP:
        def __init__(self, secret):
            self.secret = secret

        def get_hotp_token(self, intervals_no):
            key = base64.b32decode(self.secret, True)
            msg = struct.pack(">Q", intervals_no)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = ord(h[19]) & 15
            h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
            return str(h).zfill(6)

        def get_totp_token(self, t=time.time()):
            return self.get_hotp_token(int(t)//30)

        def validate(self, authcode):
            valid_keys = [self.get_totp_token(time.time() + t) for t in (-30, 0, 30)]
            return reduce(lambda x, k: x or k == authcode, valid_keys, False)

    class PSK:
        def __init__(self, secret):
            self.secret = secret

        def validate(self, authcode):
            return self.secret == authcode

    class NONE:
        def __init__(self, x=None):
            pass

        def validate(self, authcode=None):
            return True

    @staticmethod
    def validate(encryption, authcode):
        methods = {"otp": Auth.OTP,
                   "psk": Auth.PSK,
                   "none": Auth.NONE
                   }
        if encryption == "none" or len(encryption) == 1 and encryption[0] == "none":
            encryption = ["none", ""]

        method = encryption[0]
        if method in methods.keys():
            return methods[method](encryption[1]).validate(authcode)
        return False


class ContextFactory:
    def __init__(self, context):
        self.context = context

    def getContext(self):
        return self.context


class HTTPServer(resource.Resource):
    isLeaf = True

    def __init__(self, resolver):
        self.resolver = resolver
        self.domains = {i["link"]: i for i in DOMAIN_CONFIG}

    def render_GET(self, request):
        if request.uri in self.domains:
            domain_info = self.domains[request.uri]
            auth = request.getHeader('Auth') or "default"
            ip = request.getHeader('IP')
            if ip and Auth.validate(domain_info["encryption"], auth):
                if "onchange" not in domain_info:
                    domain_info["onchange"] = lambda x, y: ""
                result = self.resolver.update(domain_info["domain"], ip, domain_info["onchange"]) or "OK"
                return result
        request.setResponseCode(403)
        return "403 Forbidden"


class DNSResolver(object):
    def __init__(self):
        self.domains = {}
        # You can load saved DNS mapping here.

    def update(self, domain, ip, onchange):
        originl_ip = self.domains[domain] if domain in self.domains else ""
        self.domains[domain] = ip
        if originl_ip != ip:
            return onchange(originl_ip, ip)

    def response(self, domain):
        answer = dns.RRHeader(name=domain, payload=dns.Record_A(b'%s' % self.domains[domain], 0))
        answers = [answer]
        authority = []
        additional = []
        return answers, authority, additional

    def query(self, query, timeout=None):
        if query.type == dns.A and query.name.name in self.domains:
            return defer.succeed(self.response(query.name.name))
        else:
            return defer.fail(error.DomainError())


def main():
    resolver = DNSResolver()
    factory = server.DNSServerFactory(
        clients=[resolver]
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)
    httpserver = webserver.Site(HTTPServer(resolver))
    context = Context(TLSv1_METHOD)
    context.use_certificate_chain_file(SERVER_CONFIG["ssl_crt"])
    context.use_privatekey_file(SERVER_CONFIG["ssl_key"])

    reactor.listenUDP(SERVER_CONFIG["dns_port"], protocol)
    reactor.listenSSL(SERVER_CONFIG["http_port"], httpserver, ContextFactory(context))

    reactor.run()


if __name__ == '__main__':
    try:
        main()
    except:
        pass
