"""
Module for adding OCSP Staples to a running HAProxy instance.
"""
import threading
import logging
import socket
import errno
import os
from io import StringIO
from core.excepthandler import ocsp_except_handle
import util.functions

LOG = logging.getLogger(__name__)
SOCKET_BUFFER_SIZE = 1024


class OCSPAdder(threading.Thread):
    """
    This class is used to add a OCSP staples to a running HAProxy instance by
    sending it over a socket. It runs a thread that keeps connections to
    sockets open for each of the supplied haproxy sockets. Code from
    `collectd haproxy connection`_ under the MIT license, was used for
    inspiration.

    Tasks are taken from the :class:`core.scheduling.SchedulerThread`, as soon
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
        :kwarg core.scheduling.SchedulerThread scheduler: The scheduler object
            where we can get "haproxy-adder" tasks from **(required)**.
        """
        LOG.debug("Starting OCSPAdder thread")
        self.scheduler = kwargs.pop('scheduler', None)
        self.socket_paths = kwargs.pop('socket_paths', None)

        assert self.scheduler is not None, \
            "Please pass a scheduler to get and add proxy-add tasks."
        assert self.socket_paths is not None, \
            "The OCSPAdder needs a socket_paths dict"

        self.socks = {}
        # Open sockets and ask for a prompt to keep it open
        for key, socket_path in self.socket_paths.items():
            self.socks[key] = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socks[key].connect(socket_path)
            result = self.send(key, "prompt")
            LOG.debug("Opened prompt with result: '%s'", result)
        super(OCSPAdder, self).__init__(*args, **kwargs)

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

        while True:
            context = self.scheduler.get_task(self.TASK_NAME)
            model = context.model
            LOG.debug("Sending staple for cert:'%s'", model)

            # Open the exception handler context to run tasks likely to fail
            with ocsp_except_handle(context):
                response = self.add_staple(model)
                if response != 'OCSP Response updated!':
                    self._handle_failed_staple(model, response)
            self.scheduler.task_done(self.TASK_NAME)

    def add_staple(self, model):
        """
        Create and send the command that adds a base64 encoded OCSP staple to
        the HAProxy

        :param model: An object that has a binary string `ocsp_staple` in it
            and a filename `filename`.
        """
        command = self.OCSP_ADD.format(
            util.functions.base64(model.ocsp_staple.data))
        LOG.debug("Setting OCSP staple with command '%s'", command)
        directory = os.path.dirname(model.filename)
        return self.send(directory, command)

    def send(self, socket_key, command):
        """
        Send the command through self.socks[socket_key] (using
        self.socket_paths)

        :param str socket_key: Identifying dictionary key of the socket. This
            is typically the directory HAProxy serves certificates from.
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
        #         chunk = self.socks[socket_key].recv(SOCKET_BUFFER_SIZE)
        #         if not chunk:
        #             break
        #     except IOError as err:
        #         if err.errno not in (errno.EAGAIN, errno.EINTR):
        #             raise
        #         else:
        #             break

        # Send command
        self.socks[socket_key].sendall((command + "\n").encode())

        buff = StringIO()

        # Get new response.
        while True:
            try:
                chunk = self.socks[socket_key].recv(SOCKET_BUFFER_SIZE)
                if chunk:
                    d_chunk = chunk.decode('ascii')
                    buff.write(d_chunk)
                    # TODO: what happens if several threads are talking to
                    # HAProxy on this socket?
                    if '> ' in d_chunk:
                        break
                else:
                    break
            except IOError as err:
                if err.errno not in (errno.EAGAIN, errno.EINTR):
                    raise

        # Strip *all* \n, > and space characters from the end
        response = buff.getvalue().strip('\n> ')
        buff.close()
        LOG.debug("Received HAProxy response '%s'", response)
        return response

    @staticmethod
    def _handle_failed_staple(model, problem):
        """
        Handles a problem.

        :param str model: The certificate for which a staple was sent
        :param err,str problem: Either a Python exception or a string returned
            by HAProxy.
        """
        # TODO: What to do???
        LOG.critical("ERROR: cert '%s' has problem '%s'", model, problem)
