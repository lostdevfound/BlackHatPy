import socket
import sys
import threading
from select import select
import types
import subprocess
import ssl

# openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1

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
    """A simple client on SSL."""
    def __init__(self, targetIP, port, serverName='bhserver'):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.targetIP = targetIP
        self.serverName = serverName
        self.port = port
        # SSL implementation
        self.sslContext = ssl.create_default_context(cafile='ssl/cert.pem', capath='ssl')   # load trusted cert
        # Create an SSL socket and set server_hostname to the server name from the certificate
        self.client = self.sslContext.wrap_socket(self.client,  server_hostname=self.serverName)


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
    """Simpel server with SSL sockets"""
    def __init__(self, ipAddr='0.0.0.0', port=9999, maxClients=5, password=123456, rhostAddr=None,
                rhostPort=None, rhostServerName='bhserver'):
        if not isinstance(port, int):
            raise TypeError('The port parameter is an integer type')

        if not isinstance(ipAddr, str):
            raise TypeError('The ip parameter is a string')

        if not isinstance(maxClients, int):
            raise TypeError('maxClients parameter is an integer type')

        if not isinstance(password, int):
            raise TypeError('passowrd parameter is an integer type')

        self.ipAddr = ipAddr
        self.port = port
        self.maxClients = maxClients
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # SSL implementation
        self.sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)   # Create context for client auth
        # Load server's certificate and its private key, the password to unpack pem file is 1234
        self.sslContext.load_cert_chain(certfile='ssl/cert.pem', keyfile='ssl/key.pem', password='1234')
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
            #ssl wrap socket
            clientSocket = self.sslContext.wrap_socket(clientSocket, server_side=True)
            # Initiate the thread for the client socket and pass a function or method to be executed
            clientThread = threading.Thread(target=handler, args=(clientSocket, clientAddr, behavior))
            # Start the thread
            clientThread.start()

        # Close the socket when finished
        self.server.close()


    def clientHandler(self, clientSocket, clientAddr, behavior):
        """One of the client handler methods"""
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


    def serverLogin(self, clientSocket):
        """A simple authentication method. If no valid passwrod is provided
        The clientSocket will be closed. Since the server and the client objects
        use SSL certs this method is deprecated.
        """
        sentData = self.sendData(clientSocket, 'password:')
        if not sentData:
            clientSocket.close()

        # Receive a passwrod
        password = self.recvData(clientSocket)

        # Check if the password is valid
        if password.strip() == str(self.passowrd):
            return True
        else:
            print('Invalid password, closing connection.')
            return False
