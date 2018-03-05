# -*- coding: utf-8 -*-
"""
Module for adding OCSP Staples to a running HAProxy instance.
"""
import threading
import logging
import socket
import errno
import os
import queue
from io import StringIO
from stapled.core.excepthandler import stapled_except_handle
import stapled.core.exceptions

try:
    _ = BrokenPipeError
except NameError:
    import socket
    BrokenPipeError = socket.error

LOG = logging.getLogger(__name__)
SOCKET_BUFFER_SIZE = 1024
SOCKET_TIMEOUT = 86400


class StapleAdder(threading.Thread):
    """
    This class is used to add a OCSP staples to a running HAProxy instance by
    sending it over a socket. It runs a thread that keeps connections to
    sockets open for each of the supplied haproxy sockets. Code from
    `collectd haproxy connection`_ under the MIT license, was used for
    inspiration.

    Tasks are taken from the :class:`stapled.scheduling.SchedulerThread`, as soon
        as a task context is received, an OCSP response is read from the model
        within it, it is added to a HAProxy socket found in
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

    def __init__(self, *args, **kwargs):
        """
        Initialise the thread with its parent :class:`threading.Thread` and its
        arguments.

        :kwarg dict socket_paths: A mapping from a directory (typically the
            directory containing TLS certificates) to a HAProxy socket that
            serves certificates from that directory. These sockets are used to
            communicate new OCSP staples to HAProxy, so it does not have to be
            restarted.
        :kwarg stapled.scheduling.SchedulerThread scheduler: The scheduler object
            where we can get "haproxy-adder" tasks from **(required)**.
        """
        self.stop = False
        LOG.debug("Starting StapleAdder thread")
        self.scheduler = kwargs.pop('scheduler', None)
        self.paths = kwargs.pop('socket_paths', None)

        assert self.scheduler is not None, \
            "Please pass a scheduler to get and add proxy-add tasks."
        assert self.paths is not None, \
            "The StapleAdder needs a socket_paths dict"

        self.socks = {}
        with stapled_except_handle():
            LOG.info(self.paths.values())
            for paths in self.paths.values():
                for path in paths:
                    self.socks[path] = self._open_socket(path)
        super(StapleAdder, self).__init__(*args, **kwargs)

    def _open_socket(self, path):
        """
        Open socket located at path, and return the socket.
        Subsequently it asks for a prompt to keep the socket connection open,
        so several commands can be sent without having to close and re-open the
        socket.

        :param str path: A valid HAProxy socket path.

        :raises :exc:stapled.core.exceptions.SocketError: when the socket can
            not be opened.
        """
        sock = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM
        )
        try:
            sock.connect(path)
        except FileNotFoundError as exc:
            raise stapled.core.exceptions.SocketError(
                "Could not initialize StapleAdder with socket {}: {}".format(
                    path,
                    exc
                )
            )
        result = self.send(path, "prompt")
        LOG.debug("Opened prompt with result: '%s'", result)
        result = self.send(path, "set timeout cli {}".format(SOCKET_TIMEOUT))
        return sock

    def __del__(self):
        """
        Close the sockets on exit.
        """
        for sock in self.socks.values():
            sock.close()

    def run(self):
        """
        The main loop: send any commands that enter the command queue

        :raises ValueError: if the command queue is empty.
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
        Create and send the command that adds a base64 encoded OCSP staple to
        the HAProxy

        :param model: An object that has a binary string `ocsp_staple` in it
            and a filename `filename`.
        """
        command = self.OCSP_ADD.format(model.ocsp_staple.base64)
        LOG.debug("Setting OCSP staple with command '%s'", command)
        path = self.paths[model.cert_path]
        if path is None:
            LOG.debug("No socket set for %s", model.filename)
            return
        responses = self.send(path, command)
        for response in responses:
            if response != 'OCSP Response updated!':
                raise stapled.core.exceptions.StapleAdderBadResponse(
                    "Bad HAProxy response: '{}' from socket {}".format(
                        response,
                        path
                    )
                )

    def send(self, paths, command):
        """
        Send the command through the socket at ``path``.

        :param list paths: The path(s) to the socket(s) which should already
            be open.
        :param str command: String with the HAProxy command. For a list of
            possible commands, see the `haproxy documentation`_

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

        # Send command
        with stapled_except_handle():
            responses = []
            for path in paths:
                sock = self.socks[path]
                try:
                    sock.sendall((command + "\n").encode())
                except BrokenPipeError:
                    # Try to re-open the socket. If that doesn't work, that
                    # will raise a :exc:`~stapled.core.exceptions.SocketError`
                    LOG.info("Re-opening socket %s", path)
                    sock.close()
                    sock = self.socks[path] = self._open_socket(path)
                    # Try again, if this results in a BrokenPipeError *again*,
                    # it will be caught by stapled_except_handle
                    sock.sendall((command + "\n").encode())
                buff = StringIO()
                # Get new response.
                while True:
                    try:
                        chunk = sock.recv(SOCKET_BUFFER_SIZE)
                        if chunk:
                            d_chunk = chunk.decode('ascii')
                            buff.write(d_chunk)
                            # TODO: Find out what happens if several threads
                            # are talking to HAProxy on this socket
                            if '> ' in d_chunk:
                                break
                        else:
                            break
                    except IOError as err:
                        if err.errno not in (errno.EAGAIN, errno.EINTR):
                            raise

                # Strip *all* \n, > and space characters from the end
                response = buff.getvalue().strip('\n> ')
                LOG.debug("Received HAProxy response '%s'", response)
                responses.append()
                buff.close()
        return responses
