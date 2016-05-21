#!/usr/bin/python3.4

import argparse
import sys
import craftServer as bh

"""This is a command line tool that uses craftServer.py to launch server, proxy server or client services.
All of the services can use encrypted SSL connection and self-signed certs for authentication.
"""

# Create the arg parser
parser = argparse.ArgumentParser()
parser.description = """The command line tool that launches one of the following services: server, client and proxy.
                    All of the services support SSL encryption and certificate authentication."""

parser.add_argument('mode', type=str, help='server, client, proxy')
# flags for a server, client and proxy
parser.add_argument('-p',   '--port',      default=9999,       type=int, help='Set the port on which the host will operate')
parser.add_argument('-ip',  '--ipAddress', default='',         type=str, help='Set the IP address interface fot the host.')
parser.add_argument('-rIP', '--rhostIP',   default='',         type=str, help='The remote host IP address')
parser.add_argument('-rP',  '--rhostPort', default='',         type=str, help='The the remote host port the proxy shoulf connect')
parser.add_argument('-sn',  '--serverName',default='bhserver', type=str, help='The name of the server written in the self-signed SSL cert')
parser.add_argument('-s',   '--secure',    default=0,          type=int, help='If secure is set to 1, the host will use SSL protocol.')
parser.add_argument('-c',   '--command',   default='',         type=str, help='Execute a single command')
parser.add_argument('-pp',  '--pemPass',   default='1234',     type=str, help='Password to open SSL pem cert file')
# Handler picks an API method which will handle the client connections.
parser.add_argument('-ha',  '--handler',   default='clientHandler', type=str, help='the method for handleing clients connections')
# The behavior args picks optional methods for processing the client's recv data
parser.add_argument('-b',   '--behavior',  default='execute',  type=str, help='the method for processing the messages from clients')

args = parser.parse_args()

# Check the mode and flags provided
if args.mode == 'server':

    if args.ipAddress != '':
        # Start the server
        server = bh.Server(ipAddr=args.ipAddress, port=args.port, secure=args.secure, pemPass=args.pemPass)

        # Set the connection handler and behavior
        if args.handler == 'clientHandler' and args.behavior == 'execute':
            print('### server mode: listening on port {}'.format(args.port))
            if args.secure:
                print('### The server uses SSL.')
            server.listen(handler=server.clientHandler, behavior=server.execute)

    else:
        parser.print_help()
        print('Example: netbh.py server -ip 0.0.0.0 -p 9999')

# If not server but a client, init the client
elif args.mode == 'client':

    if args.ipAddress != '':

        print('### client mode: Connecting to {} {}'.format(args.ipAddress, args.port) )

        if (args.secure):
            print('### make sure the pem self-signed cert is setup.')

        client = bh.Client(targetIP=args.ipAddress, port=args.port, serverName=args.serverName, secure=args.secure)
        client.connect()

        if args.command != '':  # if command is provided in the shell, run a single command and exit
            client.talk(args.command)
        else:
            client.talk()   # enter in an interactive shell

    else:
        parser.print_help()
        print('Example: netbh.py client -ip 192.168.1.100 -p 9999')
