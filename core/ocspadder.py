"""
Module for adding OCSP Staples to a running HAProxy instance
"""
import threading
import logging
import socket
import errno
from io import StringIO

import util.functions

LOG = logging.getLogger()
SOCKET_BUFFER_SIZE = 1024

class OCSPAdder(threading.Thread):
    """
    This class is used to add an OCSP staple to a running HAProxy instance by
    sending it over a socket. It runs a thread that keeps 1 open socket
    connection with self.sock. Some of the code from
    `collectd haproxy connection`_ under the MIT license, was used for
    inspiration

    :param socket_path: The path to the HAProxy socket. This can also be an
        IP + portnumber (although that has not been tested yet)
    :param Queue command_queue: A queue that holds commands to send trough the
        HAProxy socket. As soon as the command_queue recieves a new command,
        it is sent to self.socket_path.

    .. _collectd haproxy connection:
       https://github.com/wglass/collectd-haproxy/blob/master/collectd_haproxy/
       connection.py
    """

    #: The name of this task in the scheduler
    TASK_NAME = 'proxy-add'

    #: The haproxy socket command to add OCSP staples. Use string.format to add
    #: the base64 encoded OCSP staple
    OCSP_ADD = 'set ssl ocsp-response {}'

    def __init__(self, *args, **kwargs):
        LOG.debug("Starting OCSPAdder thread")
        self.scheduler = kwargs.pop('scheduler', None)
        self.socket_path = kwargs.pop('socket_path', None)

        assert self.scheduler is not None, \
            "Please pass a scheduler to get and add proxy-add tasks."
        assert self.socket_path is not None, \
            "The OCSPAdder needs a socket_path"

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        super(OCSPAdder, self).__init__(*args, **kwargs)

    def __enter__(self):
        """
        The socket is opened by using "with: " on this object and automatically
        closed by self.__exit__(). This connects to HAProxy and asks for a
        prompt. The connection will stay open as long as this thread runs.
        """
        self.sock.connect(self.socket_path)
        # Open the socket and ask for a prompt
        self.sock.sendall(("prompt\n").encode())

    def __exit__(self, exception_type, exception_value, exception_trace):
        """
        Close the socket on exit.
        """
        self.sock.close()

    def run(self):
        """
        The main loop: send any commands that enter the command queue

        :raises ValueError: if the command queue is empty.
        """
        LOG.info("Started an OCSP adder thread.")

        while True:
            cert = self.scheduler.get_task(self.TASK_NAME)
            LOG.debug(
                "Sending staple to HAProxy socket '%s':\n\tcert:'%s'",
                self.socket_path, cert)
            try:
                response = self.add_staple(cert)
                if response != 'OCSP Response updated!':
                    self._handle_failed_staple(cert, response)
            except IOError as err:
                self._handle_failed_staple(cert, err)
            self.scheduler.task_done(self.TASK_NAME)

    def add_staple(self, cert):
        """
        Create and send the command that adds a base64 encoded OCSP staple to
        the HAProxy

        :param cert: An object that has a binary string ocsp_staple in it
        """
        command = self.OCSP_ADD.format(util.functions.base64(cert.ocsp_staple.data))
        LOG.debug("Setting OCSP staple with command '%s'", command)
        self.send(command)

    def send(self, command):
        """
        Send the command through self.sock (using self.socket_path)

        :param str command: String with the HAProxy command. For a list of possible
            commands, see the `haproxy documentation`_
        :raises IOError if an error occurs and it's not errno.EAGAIN or
            errno.EINTR

        .. _haproxy documentation:
           http://haproxy.tech-notes.net/9-2-unix-socket-commands/
        """
        # Empty buffer first, it's possible that other commands have been fired
        # to the same socket, we don't want the response to those commands in
        # our response string.
        while True:
            try:
                chunk = self.sock.recv(SOCKET_BUFFER_SIZE)
                if not chunk:
                    break
            except IOError as err:
                if err.errno not in (errno.EAGAIN, errno.EINTR):
                    raise
                else:
                    break

        # Send command
        self.sock.sendall((command + "\n").encode())

        buff = StringIO()

        # Get new response.
        while True:
            try:
                chunk = self.sock.recv(SOCKET_BUFFER_SIZE)
                if chunk:
                    d_chunk = chunk.decode('ascii')
                    if '> ' in d_chunk:
                        break
                    buff.write(d_chunk)
                else:
                    break
            except IOError as err:
                if err.errno not in (errno.EAGAIN, errno.EINTR):
                    raise

        response = buff.getvalue()
        buff.close()
        return response

    @staticmethod
    def _handle_failed_staple(cert, problem):
        """
        Handles a problem.

        :param str cert: The certificate for which a staple was sent
        :param err,str problem: Either a Python exception or a string returned by
            HAProxy.
        """
        # TODO: What to do???
        LOG.critical("ERROR: cert '%s' has problem '%s'", cert, problem)
