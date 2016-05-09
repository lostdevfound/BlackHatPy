# BlackHatPy
A repository inspired by Justin Seitz's book Black Hat Python

The module contains netbh.py - command line tools which is similar to Netcat utility. The utility runs on top of the blackHatPy which is an API to create servers and define their arbitrary behavior functionality. So far the API implements optional proxy like behavior or a remote shell behavior.

The communication betweeb a server and a cliet uses SSL with self-signed certificates. The code comes with the test self-signed pem certificate and a private key.

In order to run the tool from the shell and see the help:
```
python bhnet.py  -h
```

