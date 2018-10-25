"""
Track log messages and keep statistics on emitted record and levels.

Add this logging handler to keep statistics on how many message of each level
were emitted. This can help you in deciding the exit code of your application
without having to track whether errors occurred everywhere in your application.

You can also format an exit string such as:

> 5 critical error and 2 warning occurred.
"""
import logging


class ExitCodeTracker(logging.Handler):
    """Track log messages and keep statistics on emitted record and levels."""

    def __init__(self, level=logging.ERROR):
        """
        Initialise a tracker for records per log level.

        :param level int Minimum Loglevel that should be tracked.
        """
        super(ExitCodeTracker, self).__init__()
        self.setLevel(level)
        self.level = level
        self.logged = {'WARNING': 0, 'ERROR': 0, 'CRITICAL': 0}

    def emit(self, record):
        """
        Handle "emitting" records, keeps statistics per level.

        :param logging.LogRecord
        """
        if record.levelno >= self.level:
            try:
                self.logged[record.levelname] += 1
            except KeyError:
                self.logged[record.levelname] = 1

    @property
    def errors_occurred(self):
        """
        Return a count of errors that occurred.

        :returns int count of errors that occurred.
        """
        return self.logged['ERROR'] + self.logged['CRITICAL']

    @property
    def criticals_occurred(self):
        """
        Return a count of criticals that occurred.

        :returns int count of criticals that occurred.
        """
        return self.logged['CRITICAL']

    @property
    def warnings_occurred(self):
        """
        Return a count of warnings that occurred.

        :returns int count of warnings that occurred.
        """
        return self.logged['WARNING']

    def __str__(self):
        """
        Return a summary of logged criticals, errors and warnings.

        :returns str Formatted string of logged criticals, errors and warnings.
        """
        return (
            "Critical errors: {CRITICAL}, errors: {ERROR}, warnings: "
            "{WARNING}"
        ).format(**self.logged)
