# craftServer
python3.5

A repository inspired by Justin Seitz's book Black Hat Python

The module contains netbh.py - command line tools which is similar to Netcat utility. The utility runs on top of the crafterver.py which is an API to create servers and define their arbitrary behavior functionality. So far the API implements optional proxy like behavior or a remote shell behavior.

The communication between a server and a cliet uses optional SSL with self-signed certificates. The code comes with the test self-signed pem certificate and a private key.

In order to run the tool from the shell and see the help:
```
python netbh.py  -h
```

To run the SSL server with interactive shell simulation:
```
python netbh.py server -ip 0.0.0.0 -p 9999 -s 1
```
To run the SSL client:
```
python netbh.py client -ip localhost -p 9999 -s 1
```
No SSL server and client:
```
python netbh.py server -ip 0.0.0.0 -p 9999      // to run the server
python netbh.py client -ip localhost -p 9999    // to run the client
```

Note: for testing purposes the client and the server use the same cert and key
