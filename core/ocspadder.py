import threading
import logging

from io import StringIO

LOG = logging.getLogger(__name__)

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

    def __init__(self, *args, **kwargs):
        self.socket_path = kwargs['socket_path']
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.command_queue = kwargs.pop('command_queue', None)

    def __enter__(self):
        """
        The socket is opened by using "with: " on this object and automatically
        closed by self.__exit__(). This connects to HAProxy and asks for a
        prompt. The connection will stay open as long as this thread runs.
        """
        self.sock.connect(self.socket_path)
        # Open the socket and ask for a prompt
        self.sock.sendall(("prompt\n").encode())

    def __exit__(self):
        sock.close()

    def run(self, *args, **kwargs):
        """
        The main loop: send any commands that enter the command queue

        :raises ValueError: if the command queue is empty.
        """
        if self.command_queue is None:
            raise ValueError(
                "You need to pass a queue where parsed certificates can "
                "be retrieved from for renewing."
            )

        LOG.info("Started an OCSP adder thread.")

        while True:
            command = self.command_queue.get()
            LOG.debug("Sending command to HAProxy socket '%s':\n\t'%s'",
                self.socket_path, command)
            try:
                response = self.send(command)
            except IOError as err:
                self._handle_failed_staple(command, err)
            if response != 'OCSP Response updated!':
                self._handle_failed_staple(command, response)

    def send(command):
        """
        Send the command through self.sock (using self.socket_path)

        :param str command: String with the HAProxy command. For a list of possible
        commands, see the `haproxy documentation`_

        .. _haproxy documentation:
           http://haproxy.tech-notes.net/9-2-unix-socket-commands/
        """
        # Empty buffer first, it's possible that other commands have been fired
        # to the same socket, we don't want the response to those commands in
        # our response string.
        while True:
            try:
                chunk = sock.recv(SOCKET_BUFFER_SIZE)
                if not chunk:
                    break;

        # Send command
        self.sock.sendall((command + "\n").encode())

        buff = StringIO()

        # Get new response.
        while True:
            try:
                chunk = sock.recv(SOCKET_BUFFER_SIZE)
                if chunk:
                    d_chunk = chunk.decode('ascii')
                    if '> ' in d_chunk:
                        break
                    buff.write(d_chunk)
                else:
                    break
            except IOError as e:
                if e.errno not in (errno.EAGAIN, errno.EINTR):
                    self._handle_failed_staple(command

        response = buff.getvalue()
        buff.close()
        return response

    def _handle_failed_staple(self, command, problem):
        """
        Handles a problem.

        :param str command: The command that was sent
        :param err,str problem: Either a Python exception or a string returned by
            HAProxy.
        """
        # TODO: What to do???
        LOG.critical("ERROR: '%s'", problem)
