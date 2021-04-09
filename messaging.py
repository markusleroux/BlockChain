import socket
import pickle
from typing import Callable


MAX_TCP_MSG_SIZE = 2048
HandlingFunction = Callable[[socket.Socket], None]


class Messaging:
    @staticmethod
    def send(sock, obj):
        bs = pickle.dumps(obj)
        sock.sendall(len(bs).to_bytes(4) + bs)

    @staticmethod
    def receive(sock):
        """Reconstruct object from pickle data recieved by stream.

        Notes:
        - must already be listening on sock
        - does not close socket

        """
        len_bs = b''
        while len(len_bs) < 4:
            len_bs += int.from_bytes(sock.recv(32))

        len_ = int.from_bytes(len_bs)

        received = 0
        pieces = []
        while received < len_bs:
            pieces.append(sock.recv(min(MAX_TCP_MSG_SIZE, len_ - received)))
            if pieces[-1] == b'':
                raise RuntimeError()

            received += len(pieces[-1])

        return pickle.loads(b''.join(pieces))


class Server(Messaging):
    @staticmethod
    def serve(ports: dict[int, HandlingFunction], **options):
        """Use the handling functions to serve incoming tcp connections
        on specific ports.

        options
        -------
        blocking : bool (False)
            blocking or non-blocking sockets
        host : str ("")
            the host to bind to
        max_requests : int (5)


        """

        socks = dict()
        for port, f in ports.items():
            socks[port] = socket.socket()       # INET Streaming socket
            socks[port].setblocking(options.get("blocking", False))
            socks[port].bind((options.get("host", ""), port))
            socks[port].listen(options.get("max_requests", 5))

        while True:
            reads, writes, errors = ports.values(), [], []
            notified_sockets = socket.select(reads, writes, errors,
                                             options.get("timeout", 60))[0]
            for ns in notified_sockets:
                sock, addr = ns.accept()
                if ns in ports.keys():
                    ports[ns](sock)


class Client(Messaging):
    @staticmethod
    def connect(port, addr):
        sock = socket.socket()
        sock.connect((addr, port))
        return sock

    @staticmethod
    def send_receive(port, addr, obj):
        sock = Client.connect(port, addr)
        Messaging.send(sock, obj)
        response = Messaging.receive(sock)
        sock.close()
        return response
