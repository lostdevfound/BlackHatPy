import socket
import sys
import threading
from select import select
import types
import subprocess
import ssl
import os

# API for a simple server and client
# Since the server can use SSL sockets and relies on self signed certificate and a private key
# The user should generate a pem cert and a private key
# The pem self signed cert can be created by running openssl command as follows:
# openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 350

genericCert = 'cert.pem'
genericKey = 'key.pem'
TRUSTED_CERTS_PATH = 'ssl'

TRUSTED_CERTS = os.path.join(TRUSTED_CERTS_PATH, genericCert)

CLIENT_CERTKEY = os.path.join(TRUSTED_CERTS_PATH, genericKey)
CLIENT_CERTFILE = os.path.join(TRUSTED_CERTS_PATH, genericCert)

SERVER_CERTKEY = os.path.join(TRUSTED_CERTS_PATH, genericKey)
SERVER_CERTFILE = os.path.join(TRUSTED_CERTS_PATH, genericCert)

print(TRUSTED_CERTS)
class Sockets(object):
    """A base class to send and recv data"""
    def __init__(self):
        pass

    @staticmethod
    def sendData(sock, data):
        """Send data from the socket"""
        if not isinstance(sock, socket.socket):
            raise TypeError('First argument should be a soket object')

        if not isinstance(data, str):
            raise TypeError('Second argument should be a string')

        bytedata = data.encode()

        try:
            sock.send(bytedata)
            return True
        except Exception as e:
            print('Could not send bytedata')
            print(e)
            sock.close()
            return False


    @staticmethod
    def recvData(sock, dataSize=1024):
        """Receive data"""
        if not isinstance(sock, socket.socket):
            raise TypeError('The parameter should be a socket object')

        recvData = 'failedRecv'

        try:
            recvData = sock.recv(dataSize).decode('utf-8')
        except Exception as e:
            print('Could not receive data')
            print(e)
            sock.close()
        return recvData


class Client(Sockets):
    """A simple client. If server is running in SSL mode. The client should be initialized
    with secure parameter set to 1. The client sends the remote commands to the server
    """
    def __init__(self, targetIP, port, serverName='bhserver', secure=0, pemPass='1234'):
        if not isinstance(targetIP, str):
            raise TypeError('targetIP should be a string')

        if not isinstance(port, int):
            raise TypeError('port parameter should be an int type')

        if not isinstance(serverName, str):
            raise TypeError('serverName parameter should be a str')

        if not isinstance(secure, int):
            raise TypeError('secure parameter should be a str')

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.targetIP = targetIP
        self.serverName = serverName
        self.port = port
        self.secure = secure
        self.pemPass = pemPass

        if self.secure:
            # SSL implementation
            self.sslContext = ssl.create_default_context(cafile=TRUSTED_CERTS, capath=TRUSTED_CERTS_PATH)   # load trusted cert
            self.sslContext.load_cert_chain(certfile=CLIENT_CERTFILE, keyfile=CLIENT_CERTKEY, password=pemPass)   # load self identificating certs
            # Create an SSL socket and set server_hostname to the server name from the certificate
            self.client = self.sslContext.wrap_socket(self.client,  server_hostname=self.serverName )


    def connect(self, login=1):
        """Connect to a specified ip addr and port"""
        try:
            self.client.connect((self.targetIP, self.port))
            print('Connected to {} {}'.format(self.serverName, self.port))
        except Exception as e:
            print('Could not connect to a target.')
            print(e)


    def talk(self, singleMessage=''):
        """The method detects if first recieve or send data.
        The singleMessage parameter can carry an external stdin stream or external argument.
        If singleMessage is not specified, the method will get get the input() later.
        """
        if not isinstance(singleMessage, str):
            raise TypeError('message should be a string')

        readSockets = [self.client]
        # Send and recieve data
        while True:
            readables, writables, exceptions = select(readSockets, [], [], 1)
            # Receive if a socket has data in the buffer
            if self.client in readables:
                recvData = self.recvData(self.client)
                # Print the assembled message
                print(recvData, end='')

            # If an argument for SingleMessage is provided, send it and exit
            if singleMessage != '':
                self.sendData(self.client, singleMessage)
                self.client.close()
                return

            # If no messeg provided get the message from a user and send it
            message = input(':')
            # Return if quit or exit words are provided
            if message == 'quit' or message == 'exit':
                self.client.close()
                return

            self.sendData(self.client, message)

            # Receive response from the command execution
            recvData = ''

            while True:
                fragment = self.recvData(self.client)
                recvData += fragment
                if len(fragment) < 1024:
                    break
            # Print the output of the command
            print(recvData)


class Server(Sockets):
    """Simpel server with SSL sockets. By default the server uses regular TCP sockets.
    If secure parameter is set to 1, the server will rely on a self-signed certificate.
    The server executes remote commands sent from the client.
    """
    def __init__(self, ipAddr='0.0.0.0', port=9999, maxClients=5, pemPass='1234', rhostAddr=None,
                rhostPort=None, rhostServerName='bhserver', secure=0):
        if not isinstance(port, int):
            raise TypeError('The port parameter should be an integer type')

        if not isinstance(ipAddr, str):
            raise TypeError('The ip parameter should be a string')

        if not isinstance(maxClients, int):
            raise TypeError('maxClients parameter should be an integer type')

        if not isinstance(secure, int) and not secure == 0 and not secure == 1:
            raise ValueError('secure parameter should be 0 or 1')

        if not isinstance(rhostServerName, str):
            raise TypeError('rhostServerName should be a str')


        self.ipAddr = ipAddr
        self.port = port
        self.maxClients = maxClients
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure = secure
        self.pemPass = pemPass

        # Use SSL socket if secure is set to 1
        if self.secure:
            # SSL implementation
            self.sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, capath=TRUSTED_CERTS_PATH, cafile=TRUSTED_CERTS)   # Create default context and load trusted certs
            # Load server's certificate and its private key, the password to unpack pem file is 1234
            self.sslContext.load_cert_chain(certfile=SERVER_CERTFILE, keyfile=SERVER_CERTKEY, password=self.pemPass)
            # force the client to provide its cert
            self.sslContext.verify_mode=ssl.CERT_REQUIRED

        # Proxy server optional attributes
        self.rhostAddr = rhostAddr
        self.rhostPort = rhostPort
        self.rhostServerName = rhostServerName


    def listen(self, handler, behavior='None'):
        """Start listening for incoming connections. handler
        parameter sets the methods which the server will use when a client
        connects to it. behavior parameter further specifies the behavior of
        the handler
        """
        if behavior != 'None':
            if not isinstance(behavior, types.MethodType) and not isinstance(behavior, types.FunctionType):
                raise TypeError('The parameter should be a method type')
        if not isinstance(handler, types.MethodType) and not isinstance(behavior, types.FunctionType):
            raise TypeError('The parameter should be a method type')

        self.server.bind((self.ipAddr, self.port))
        self.server.listen(self.maxClients)

        while True:
            clientSocket, clientAddr = self.server.accept()

            # SSL wrap socket if self.secure is 1
            if self.secure:
                clientSocket = self.sslContext.wrap_socket(clientSocket, server_side=True)

            # Initiate the thread for the client socket and pass a function or method to be executed
            clientThread = threading.Thread(target=handler, args=(clientSocket, clientAddr, behavior))
            # Start the thread
            clientThread.start()

        # Close the socket when finished
        self.server.close()


    def clientHandler(self, clientSocket, clientAddr, behavior):
        """The method would make the server to execute the remote commands from the client."""
        # Keep talking data
        while True:
            # Send data
            dataSent = self.sendData(clientSocket, '$')
            if not dataSent:
                return
            # Receive data
            recvData = self.recvData(clientSocket)
            # Print data and keep talking or close connection
            if recvData:
                # Execute some kind of a command
                output = behavior(recvData)
                sentData = self.sendData(clientSocket, output)

                if sentData:
                    print('[*]:', output)
                else:
                    print('[!] Could not send data')
            else:
                print('Connection with {} is closed'.format(clientAddr))
                clientSocket.close()
                return


    def proxyHandler(self, clientSocket, clientAddr, behavior=None):
        """The method would launch a server in a proxy mode. The client connects
        to the proxy and proxy would bridge the client and a remote server"""
        # Initialize a new connection to a rhost
        rhostSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Wrap the rhost socket into SSL socket if secure parameter is set to 1
        if self.secure:
            # SSL implementation
            sslContext = ssl.create_default_context(cafile='ssl/cert.pem', capath='ssl')
            rhostSocket = sslContext.wrap_socket(rhostSocket,  server_hostname=self.rhostServerName)

        rhostSocket.connect((self.rhostAddr, self.rhostPort))

        readSockets = [rhostSocket, clientSocket]
        writeSockets = [rhostSocket, clientSocket]

        while True:

            readable, writable, exceptions = select(readSockets, writeSockets, [])

            for sock in readable:
                # If rhost is sending data
                if sock == rhostSocket:
                    # Receive from rhos
                    recvData = self.recvData(sock)
                    print ('Data from rhost:',  recvData)
                    # Send data to the client
                    dataSent = self.sendData(clientSocket, '=>'+ recvData)
                    if not dataSent:
                        return

                elif sock == clientSocket:
                    # Receive data from the client
                    recvData = self.recvData(clientSocket)
                    # Forward the data to the rhost
                    if recvData:
                        dataSent = self.sendData(rhostSocket, recvData)
                        print('data sent to rhost: ', recvData)
                    else:
                        print('No data recevied closing the connection with {}'.format(clientAddr))
                        return


    @staticmethod
    def execute(data):
        """The behavioral method that would execute the incoming data. This method is passed
        as an argument inside clientHander method
        """
        data = data.strip()

        try:
            output = subprocess.check_output(data, stderr=subprocess.STDOUT, shell=True).decode('utf-8')
        except:
            output = 'Failed to execute the command.'

        return output
