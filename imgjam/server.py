import gevent
from gevent import monkey
monkey.patch_all(thread=False)

import socket, os, os.path, sys
from cStringIO import StringIO
from gevent.server import StreamServer
from scapy.all import *

HTTP_PORT = 8888
HTTPS_PORT = 8899

SINGLE = 1
DIR = 2

PATH = sys.argv[1]

def gen_response(PATH):
    MODE = SINGLE if "." in PATH.split("/")[-1] else DIR

    if MODE == DIR:
        IMAGES = []
        PATH += "/" if not PATH.endswith("/") else ""
        for fname in os.listdir(PATH):
            with open(PATH + fname, "rb") as f:
                ext = os.path.splitext(fname)[1][1:].upper()
                data = f.read()
                IMAGES.append((data, ext, len(data)))
    else:
        with open(PATH, "rb") as f:
            IMAGE = f.read()
            ext = os.path.splitext(PATH)[1][1:].upper()
            length = len(IMAGE)

    content_types = { "JPG": "image/jpeg",
                      "JPEG": "image/jpeg",
                      "PNG": "image/png",
                      "GIF": "image/gif"
                    }

    HTTP_RESP =  "HTTP/1.1 200 OK\r\n"
    HTTP_RESP += "Server: Apache/2.2.16\r\n"
    HTTP_RESP += "Vary: Accept-Encoding\r\n"
    HTTP_RESP += "Content-Type: %s\r\n"
    HTTP_RESP += "Content-Length: %d\r\n"
    HTTP_RESP += "\r\n"

    try:
        if MODE == DIR:
            resp = [(HTTP_RESP % (content_types[ext], length)) + img 
                         for img, ext, length in IMAGES]
        else:
            resp = (HTTP_RESP % (content_types[ext], length)) + IMAGE
        return resp, MODE
    except KeyError:
        raise IOError("One or more files does not have an image extension")

response, MODE = gen_response(PATH)

def serve_image(sock, address):
    if MODE == DIR:
        responses = response
        resp = random.choice(responses)
    else:
        resp = response

    print "Redirected %s" % address[0]
    try:
        sock.recv(32768)
        sock.sendall(resp)
        sock.shutdown(socket.SHUT_WR)
    except:
        pass
    finally:
        sock.close()

    
def start_server():
    keyfile = os.path.join(os.path.dirname(__file__), "server.key")
    certfile = os.path.join(os.path.dirname(__file__), "server.crt")
    try:
        http_server = StreamServer(("", HTTP_PORT), serve_image, spawn=1000)
        https_server = StreamServer(("", HTTPS_PORT), serve_image,
                      keyfile=keyfile, certfile=certfile, spawn=1000)
        print ("Serving %s '%s' on ports %d, %d" % 
            ("directory" if MODE == DIR else "file", PATH, HTTP_PORT, HTTPS_PORT))
        
        #only way to silence annoying SSL exception tracebacks that I know of
        sys.stderr = StringIO()
        
        http_server.start()
        https_server.serve_forever()
    except KeyboardInterrupt:
        print "Shutting down server..."

if __name__ == "__main__":
    start_server()
