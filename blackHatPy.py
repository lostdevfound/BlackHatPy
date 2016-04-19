import socket
import sys
import threading
from select import select

#
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
        except:
            print('Could not send bytedata')
            sock.close()
            return False


    @staticmethod
    def recvData(sock):
        """Receive data"""
        if not isinstance(sock, socket.socket):
            raise TypeError('The parameter should be a socket object')

        recvData = 'failedRecv'

        try:
            recvData = sock.recv(1024).decode('utf-8')
        except:
            print('Could not receive data')
            sock.close()
        return recvData


class Client(Sockets):
    """A simple client socket"""
    def __init__(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    def connect(self, targetIP, port, login=1):
        """Connect to a specified ip addr and port"""
        try:
            self.client.connect((targetIP, port))
            print('Connected to {} {}'.format(targetIP, port))
        except:
            print('Could not connect to a target.')

        if login:
            self.login()


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

                # Keep receiving until there is no more data in the buffer
                recvData = ''
                while self.client in readables:
                    # recvData += self.client.recv(1024).decode('utf-8')
                    recvData += self.recvData(self.client)
                    readables, writables, exceptions = select([self.client], [], [], .5)

                # Print the assembled message
                print(recvData, end='')

            # If an argument for SingleMessage is provided, send it and exit
            if singleMessage != '':
                self.sendData(self.client, singleMessage)
                self.client.close()
                return

            # If no messeg provided get the message from a user and send it
            message = input()
            # message = input()

            if message == 'quit' or message == 'exit':
                self.client.close()
                return

            self.sendData(self.client, message)


    def login(self):
        """The method get's the input from the user for the password"""
        recvData = self.recvData(self.client)
        print(recvData, end='')
        # Get a user password input
        password = input('')

        if password:
            self.sendData(self.client, password)


class Server(Sockets):
    """Simpel server"""
    def __init__(self, ipAddr='0.0.0.0', port=9999, maxClients=5, password=123456):
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
        self.passowrd = password


    def listen(self, handler):
        """ Start listening for incoming connections.
        handler parameter defines server behavior when a cient connects
        to the server
        """
        if not isinstance(handler, method):
            raise TypeError('The parameter should be a method type')

        self.server.bind((self.ipAddr, self.port))
        self.server.listen(self.maxClients)

        while True:
            clientSocket, clientAddr = self.server.accept()
            # Initiate the thread for the client socket
            clientThread = threading.Thread(target=handler, args=(clientSocket, clientAddr))
            # Start the thread
            clientThread.start()

        # Close the socket when finished
        self.server.close()


    def clientHandlerEcho(self, clientSocket, clientAddr):
        """One of the handler methods that simply echo client's messegaes"""
        # Authentication
        if not self.serverLogin(clientSocket):
            clientSocket.close()
            return

        # Keep talking data
        while True:
            # Send data
            dataSent = self.sendData(clientSocket, '$:')
            if not dataSent:
                return
            # Receive data
            recvData = self.recvData(clientSocket)

            # Print data and keep talking or close connection
            if recvData:
                print('Data from {}:'.format(clientAddr), recvData)
            else:
                print('Connection with {} is closed'.format(clientAddr))
                clientSocket.close()
                return


    def serverLogin(self, clientSocket):
        """A simple authentication method. If no valid passwrod is provided
        The clientSocket will be closed
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
