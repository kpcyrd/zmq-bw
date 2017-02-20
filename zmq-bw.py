#!/usr/bin/env python3
import argparse
import zmq
import zmq.auth
import json
import time
import sys
import os


class SpeedDB(object):
    def __init__(self, ifaces):
        self.ifaces = [Interface(iface) for iface in ifaces]

    def pack(self):
        return {x.iface: x.poll() for x in self.ifaces}


class Interface(object):
    KERNEL_PATH = '/sys/class/net/%s/statistics/%s'
    KEYS = ['rx_bytes', 'tx_bytes']

    def __init__(self, iface):
        self.mem = {}
        self.iface = iface
        self.poll()

    def _delta(self, key):
        x = self._poll(key)
        delta = x - self.mem.get(key, 0)
        self.mem[key] = x
        return delta

    def _poll(self, value):
        with open(self.KERNEL_PATH % (self.iface, value)) as f:
            return int(f.read().strip())

    def poll(self):
        return {k: self._delta(k) for k in self.KEYS}


class Crypto(object):
    def __init__(self, server_secret, client_public):
        self.server = zmq.auth.load_certificate(server_secret)
        self.client = zmq.auth.load_certificate(client_public)

    def apply(self, z):
        client_public, client_secret = self.client
        z.curve_secretkey = client_secret
        z.curve_publickey = client_public

        server_public, _ = self.server
        z.curve_serverkey = server_public


class Queue(object):
    def __init__(self, dest, node, crypto, dry=False):
        ctx = zmq.Context()
        self.node = node
        self.dry = dry

        self.z = z = ctx.socket(zmq.PUSH)
        if crypto:
            crypto.apply(z)
        z.connect(dest)

    def send(self, speed):
        data = {
            'origin': self.node,
            'when': int(time.time()),
            'data': speed.pack()
        }
        if self.dry:
            print(json.dumps(data), flush=True)
        else:
            self.z.send_json(data)


def gen(args):
    os.umask(0o7)
    return zmq.auth.create_certificates(args.path, args.name)


def beacon(args):
    if args.key and args.client_key:
        crypto = Crypto(args.key, args.client_key)
    else:
        crypto = None
        if not args.dry:
            print('crypto disabled', file=sys.stderr, flush=True)

    z = Queue(args.endpoint, args.name, crypto, dry=args.dry)
    ifaces = args.ifaces if args.ifaces else os.listdir('/sys/class/net/')
    speed = SpeedDB(ifaces)

    while True:
        z.send(speed)
        time.sleep(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='stream traffic')
    subparsers = parser.add_subparsers()

    parser_gen = subparsers.add_parser('gen', description='generate client key')
    parser_gen.add_argument('path', nargs='?', help='/etc/zmq-bw')
    parser_gen.add_argument('name', nargs='?', help='client')
    parser_gen.set_defaults(func=gen)

    parser_beacon = subparsers.add_parser('beacon', description='beacon stats to endpoint')
    parser_beacon.add_argument('endpoint', help='tcp://127.0.0.1:8733')
    parser_beacon.add_argument('name', help='server name')
    parser_beacon.add_argument('ifaces', nargs='*', help='interfaces to monitor')
    parser_beacon.add_argument('-k', '--key', help='server public key')
    parser_beacon.add_argument('-c', '--client-key', help='client secret key')
    parser_beacon.add_argument('-n', '--dry', action='store_true', help='print to stdout')
    parser_beacon.set_defaults(func=beacon)

    args = parser.parse_args()
    args.func(args)
