#!/usr/bin/env python
import os
import signal
import errno
import socket
import sys
import StringIO

try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

def child_reaper(signo, frame):
    # wait for as much terminated child as possible,
    # because SIGCHLD are not queued, we can miss some of them.
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except OSError:
            return

        if pid == 0:
            return

        print(
                'Child {pid} terminated with status {status}'
                '\n'.format(pid=pid, status=status)
        )

class ClientConnection(object):
    def __init__(self, ipaddr, port, connection):
        self.ipaddr = ipaddr
        self.port = port
        self.connection = connection
        self.parser = HttpParser()

class WSGIServer(object):
    def __init__(self, addr):
        self.listen_ip, self.port = addr.split(':')
        self.listen_port = int(self.port)
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind((self.listen_ip, self.listen_port))
        self.listen_socket.listen(10)

    def set_app(self, application):
        self.application = application

    def serve_forever(self):
        listen_socket = self.listen_socket
        print('Serving HTTP on port {port}...'.format(port=self.listen_port))
        print('Server PID: {pid}'.format(pid=os.getpid()))

        signal.signal(signal.SIGCHLD, child_reaper)

        while True:
            try:
                conn, addr = listen_socket.accept()
            except IOError as e:
                code, msg = e.args
                if code == errno.EINTR:
                    continue
                else:
                    raise

            client_connection = ClientConnection(addr[0], addr[1], conn)
            pid = os.fork()
            if pid == 0: # child
                listen_socket.close() # close the child copy
                self.handle_request(client_connection)
                os._exit(0)
            else:
                client_connection.connection.close() # child take ownership of this socket
            print('Connection from {}'.format(addr))

    def handle_request(self, client_connection):
        print('Worker PID: {pid}'.format(pid=os.getpid()))
        client_connection.body = ''

        while True:
            data = client_connection.connection.recv(1024)
            if data is None:
                break

            recved = len(data)
            nparsed = client_connection.parser.execute(data, recved)
            assert nparsed == recved

            if client_connection.parser.is_partial_body():
                self.body.append(client_connection.parser.recv_body())

            if client_connection.parser.is_message_complete():
                break

        env = self.get_environ(client_connection)
        result = self.application(env, self.start_response)
        self.finish_response(client_connection, result)

    def start_response(self, status, response_headers, exc_info=None):
        server_headers = [
                ('Server', 'WSGIServer 0.1')
        ]
        self.headers = [status, response_headers + server_headers]

    def finish_response(self, client_connection, result):
        try:
            status, response_headers = self.headers
            response = 'HTTP/1.1 {status}\r\n'.format(status=status)
            for header in response_headers:
                response += '{0}: {1}\r\n'.format(*header)
            response += '\r\n'

            for data in result:
                response += '{}\r\n'.format(data)

            print(''.join(
                '> {line}\n'.format(line=line)
                for line in response.splitlines()
                ))
            client_connection.connection.sendall(response)
        finally:
            client_connection.connection.close()

    def get_environ(self, client_connection):
        env = {}

        env['REQUEST_METHOD'] = client_connection.parser.get_method()
        env['PATH_INFO'] = client_connection.parser.get_path()
        env['QUERY_STRING'] = client_connection.parser.get_query_string()
        env['SERVER_PROTOCOL'] = 'http'
        env['SERVER_NAME'] = self.listen_ip
        env['SERVER_PORT'] = str(self.listen_port)

        env['wsgi.version'] = (1, 0)
        env['wsgi.url_scheme'] = 'http'
        env['wsgi.input'] = StringIO.StringIO(client_connection.body)
        env['wsgi.errors'] = sys.stderr
        env['wsgi.multithread'] = False
        env['wsgi.multiprocess'] = False
        env['wsgi.run_once'] = False

        return env

def make_server(addr, application):
    server = WSGIServer(addr)
    server.set_app(application)
    return server

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('Provide a WSGI application object as module:callable')
    application_path = sys.argv[1]
    module_name, function = application_path.split(':')

    module = __import__(module_name)
    application = getattr(module, function)
    if hasattr(application, '__call__') is False:
        sys.exit('module \'{}\' has no callable \'{}\''.format(module_name, function))

    httpd = make_server('0.0.0.0:1234', application)
    httpd.serve_forever()
