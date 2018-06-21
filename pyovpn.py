#!/usr/bin/env python3

import json
import os
import random
import string
import subprocess
import tarfile
import urllib.request

COMMON_CONF = '''\
dev tun
proto udp
cipher AES-256-CBC
auth SHA256
compress lz4
verb 3
persist-key
persist-tun
tls-version-min 1.2
'''
SERVER_CONF = '''\
port 1194
server 10.8.0.0 255.255.255.0
keepalive 10 120
remote-cert-tls client
user nobody
group nogroup
crl-verify /etc/openvpn/crl.pem
key-direction 0
'''
CLIENT_CONF = '''\
client
remote %(hostname)s 1194
resolv-retry infinite
nobind
remote-cert-tls server
verify-x509-name %(name)s name
'''
INLINE_CONF = '''\
<ca>
%(ca)s
</ca>
<cert>
-----BEGIN CERTIFICATE-----
%(cert)s
-----END CERTIFICATE-----
</cert>
<key>
%(key)s
</key>
<tls-crypt>
%(tlskey)s
</tls-crypt>
'''
EASYRSAURL = 'https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz'


class PyOvpn(object):

    def __init__(self, dest):
        self.dest = dest
        self.config = os.path.join(self.dest, 'config.json')

    def setup_easyrsa(self):
        easyrsa_tgz = os.path.join(self.dest, 'easyrsa.tgz')
        urllib.request.urlretrieve(EASYRSAURL, easyrsa_tgz)
        tar = tarfile.open(easyrsa_tgz)
        tar.extractall(self.dest)
        easyrsa_dest = os.path.join(self.dest, 'easyrsa')
        os.rename(os.path.join(self.dest, tar.getnames()[0]), easyrsa_dest)
        os.remove(easyrsa_tgz)
        self.easyrsa(['--batch', 'init-pki'])
        self.easyrsa(['--batch', 'build-ca', 'nopass'])

    def easyrsa(self, args):
        subprocess.check_call(['easyrsa/easyrsa'] + args, cwd=self.dest)

    def read(self, path):
        with open(os.path.join(*[self.dest] + path)) as f:
            return f.read().strip()

    def read_cert(self, name):
        cert = self.read(['pki', 'issued', name + '.crt'])
        return cert.split('-----')[-3].strip()

    def _inline_conf(self, name):
      return INLINE_CONF % {
          'ca': self.read(['pki', 'ca.crt']),
          'cert': self.read_cert(name),
          'key': self.read(['pki', 'private', name + '.key']),
          'tlskey': self.read(['tls.key'])
      }

    def generate_server(self, hostname):
        os.makedirs(self.dest)
        self.setup_easyrsa()
        # Generate a random, alphanumeric identifier of 16 characters for this server so that we can use verify-x509-name later that is unique for this server installation. Source: Earthgecko (https://gist.github.com/earthgecko/3089509)
        server_name = 'server_%s' % ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
        with open(self.config, 'w') as f:
            json.dump({
              'server_name': server_name,
              'hostname': hostname
            }, f)

        self.easyrsa(['build-server-full', server_name, 'nopass'])
        subprocess.check_call(['openvpn', '--genkey', '--secret', os.path.join(self.dest, 'tls.key')])
        with open(os.path.join(self.dest, 'server.conf'), 'w') as f:
            f.write(COMMON_CONF + SERVER_CONF + self._inline_conf(server_name))

    def generate_client(self, name):
        with open(self.config) as f:
          config = json.load(f)
        self.easyrsa(['build-client-full', name, 'nopass'])
        with open(os.path.join(self.dest, name + '.ovpn'), 'w') as f:
            f.write(COMMON_CONF + 
                CLIENT_CONF % {
                    'name': config['server_name'],
                    'hostname': config['hostname']
                } + 
                self._inline_conf(name))

    def revoke(self, name):
        self.easyrsa(['--batch', 'revoke', name])
        self.easyrsa(['gen-crl'])

    def list_(self):
        print(self.read(['pki', 'index.txt']))

    def crl(self):
        self.easyrsa(['gen-crl'])
        print(self.read(['pki', 'crl.pem']))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Generate openvpn configuration')
    parser.add_argument('dest', metavar='DEST', type=str,
                        help='destination for data')
    parser.add_argument('action', metavar='ACTION', type=str, nargs='+',
                        help='server hostname|client name')
    args = parser.parse_args()
    ovpn = PyOvpn(args.dest)
    actions = {
        'server': ovpn.generate_server,
        'client': ovpn.generate_client,
        'revoke': ovpn.revoke,
        'list': ovpn.list_,
        'crl': ovpn.crl
    }
    if args.action[0] in actions:
        actions[args.action[0]](*args.action[1:])
