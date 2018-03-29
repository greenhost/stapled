# -*- coding: utf-8 -*-
"""
Module for adding OCSP Staples to a running HAProxy instance.
"""
import threading
import logging
import socket
import errno
import queue
from io import StringIO
from stapled.core.excepthandler import stapled_except_handle
import stapled.core.exceptions

try:
    _ = BrokenPipeError
except NameError:
    BrokenPipeError = socket.error

LOG = logging.getLogger(__name__)
SOCKET_BUFFER_SIZE = 1024
SOCKET_TIMEOUT = 86400


class StapleAdder(threading.Thread):
    """
    Add OCSP staples to a running HAProxy instance by sending it over a socket.

    It runs a thread that keeps connections to sockets open for each of the
    supplied haproxy sockets. Code from `collectd haproxy connection`_ under
    the MIT license, was used for inspiration.

    Tasks are taken from the :class:`stapled.scheduling.SchedulerThread`, as
        soon as a task context is received, an OCSP response is read from the
        model within it, it is added to a HAProxy socket found in
        self.socks[<certificate directory>].

    .. _collectd haproxy connection:
       https://github.com/wglass/collectd-haproxy/blob/master/collectd_haproxy/
       connection.py
    """

    #: The name of this task in the scheduler
    TASK_NAME = 'proxy-add'

    #: The haproxy socket command to add OCSP staples. Use string.format to add
    #: the base64 encoded OCSP staple
    OCSP_ADD = 'set ssl ocsp-response {}'

    #: Predefines commands to send to sockets just after opening them.
    CONNECT_COMMANDS = [
        "prompt",
        "set timeout cli {}".format(SOCKET_TIMEOUT)
    ]

    def __init__(self, *args, **kwargs):
        """
        Initialise the thread and its parent :class:`threading.Thread`.

        :kwarg dict haproxy_socket_mapping: A mapping from a directory
            (typically the directory containing TLS certificates) to a HAProxy
            socket that serves certificates from that directory. These sockets
            are used to communicate new OCSP staples to HAProxy, so it does not
            have to be restarted.
        :kwarg stapled.scheduling.SchedulerThread scheduler: The scheduler
            object where we can get "haproxy-adder" tasks from **(required)**.
        """
        self.stop = False
        LOG.debug("Starting StapleAdder thread")
        self.scheduler = kwargs.pop('scheduler', None)
        self.haproxy_socket_mapping = kwargs.pop(
            'haproxy_socket_mapping', None
        )

        assert self.scheduler is not None, \
            "Please pass a scheduler to get and add proxy-add tasks."
        assert self.haproxy_socket_mapping is not None, \
            "The StapleAdder needs a haproxy_socket_mapping dict"

        self.socks = {}
        for paths in self.haproxy_socket_mapping.values():
            for path in paths:
                with stapled_except_handle():
                    self._open_socket(path)

        super(StapleAdder, self).__init__(*args, **kwargs)

    def _re_open_socket(self, path):
        """
        Re-open socket located at path, and return the socket.
        Closes open sockets and wraps appropriate logging arount the
        ``_open_socket`` method.

        :param str path: A valid HAProxy socket path.
        :return socket.socket: An open socket.
        :raises :exc:stapled.core.exceptions.SocketError: when the socket can
            not be opened.
        """
        # Try to re-open the socket. If that doesn't work, that
        # will raise a :exc:`~stapled.core.exceptions.SocketError`
        LOG.info("Re-opening socket %s", path)
        try:
            sock = self.socks[path]
            sock.close()
        except (KeyError, UnboundLocalError):
            # Socket not openend, no need to close anything.
            pass
        # Open socket again..
        return self._open_socket(path)

    def _open_socket(self, path):
        """
        Open socket located at path, and return the socket.

        Subsequently it asks for a prompt to keep the socket connection open,
        so several commands can be sent without having to close and re-open the
        socket.

        :param str path: A valid HAProxy socket path.
        :return socket.socket: An open socket.
        :raises :exc:stapled.core.exceptions.SocketError: when the socket can
            not be opened.
        """
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(path)
            result = []
            for command in self.CONNECT_COMMANDS:
                result.extend(self._send(sock, command)
            # Results (index 1) come per path (index 0), we need only results
            result = [res[1] for res in result]
            # Indented and on separate lines or None if an empty list
            result = "\n\t{}".format("\n\t".join(result)) if result else "None"
            LOG.debug("Opened prompt with result: %s", result)
            self.socks[path] = sock
            return sock
        except (BrokenPipeError, OSError, IOError) as exc:
            raise stapled.core.exceptions.SocketError(
                "Could not initialize StapleAdder with socket {}: {}".format(
                    path,
                    exc
                )
            )

    def __del__(self):
        """Close the sockets on exit."""
        for sock in self.socks.values():
            sock.close()

    def run(self):
        """
        Send any commands that enter the command queue.

        This is the stapleadder thread's main loop.
        """
        LOG.info("Started an OCSP adder thread.")

        while not self.stop:
            try:
                context = self.scheduler.get_task(self.TASK_NAME, timeout=0.25)
                model = context.model
                LOG.debug("Sending staple for cert:'%s'", model)

                # Open the exception handler context to run tasks likely to
                # fail
                with stapled_except_handle(context):
                    self.add_staple(model)
                self.scheduler.task_done(self.TASK_NAME)
            except queue.Empty:
                pass
        LOG.debug("Goodbye cruel world..")

    def add_staple(self, model):
        """
        Create and send base64 encoded OCSP staple to the HAProxy.

        :param model: An object that has a binary string `ocsp_staple` in it
            and a filename `filename`.
        """
        command = self.OCSP_ADD.format(model.ocsp_staple.base64)
        LOG.debug("Setting OCSP staple with command '%s'", command)
        paths = self.haproxy_socket_mapping[model.cert_path]
        if not paths:
            LOG.debug("No socket set for %s", model.filename)
            return
        responses = self.send(paths, command)
        for path, response in responses:
            if response != 'OCSP Response updated!':
                raise stapled.core.exceptions.StapleAdderBadResponse(
                    "Bad HAProxy response: '{}' from socket {}".format(
                        response,
                        path
                    )
                )

    def _send(self, sock, command):
        """
        Send the command through the ``socket`` and handle response.

        :param list sock: An already opened socket.
        :param str command: String with the HAProxy command. For a list of
            possible commands, see the `haproxy documentation`_
        :return list: List of tuples containing path and response from HAProxy.
        :raises IOError if an error occurs and it's not errno.EAGAIN or
            errno.EINTR

        .. _haproxy documentation:
            http://haproxy.tech-notes.net/9-2-unix-socket-commands/

        """
        sock.sendall((command + "\n").encode())
        buff = StringIO()
        # Get new response.
        while True:
            try:
                chunk = sock.recv(SOCKET_BUFFER_SIZE)
                if chunk:
                    decoded_chunk = chunk.decode('ascii')
                    buff.write(decoded_chunk)
                    # TODO: Find out what happens if several threads
                    # are talking to HAProxy on this socket
                    if '> ' in decoded_chunk:
                        break
                else:
                    break
            except IOError as err:
                if err.errno not in (errno.EAGAIN, errno.EINTR):
                    raise

        # Strip *all* \n, > and space characters from the end
        response = buff.getvalue().strip('\n> ')
        buff.close()
        return response

    def send(self, paths, command):
        """
        Send the command through the sockets at ``paths``.

        :param str|list paths: The path(s) to the socket(s) which should
            already be open.
        :param str command: String with the HAProxy command. For a list of
            possible commands, see the `haproxy documentation`_
        :return list: List of tuples containing path and response from HAProxy.
        :raises IOError if an error occurs and it's not errno.EAGAIN or
            errno.EINTR

        .. _haproxy documentation:
            http://haproxy.tech-notes.net/9-2-unix-socket-commands/

        """
        # Empty buffer first, it's possible that other commands have been fired
        # to the same socket, we don't want the response to those commands in
        # our response string.
        # FIXME: This would be nice, but is tricky because the socket seems to
        # close if the recv call times out. Otherwise the socket stays open but
        # the recv call is blocking...
        # If this problem occurs, the easiest way is probably to open a socket
        # each time we want to communicate...
        # while True:
        #     try:
        #         chunk = self.socks[path].recv(SOCKET_BUFFER_SIZE)
        #         if not chunk:
        #             break
        #     except IOError as err:
        #         if err.errno not in (errno.EAGAIN, errno.EINTR):
        #             raise
        #         else:
        #             break
        with stapled_except_handle():
            responses = []
            if not isinstance(paths, (list, tuple)):
                paths = [paths]
            for path in paths:
                try:
                    sock = self.socks[path]
                    response = self._send(sock, "{}\n".format(command))
                except (BrokenPipeError, KeyError):
                    sock = self._re_open_socket(path)
                    response = self._send(sock, "{}\n".format(command))

                LOG.debug("Received HAProxy response '%s'", response)
                responses.append((path, response))
            return responses
