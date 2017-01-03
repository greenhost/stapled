import logging
LOG = logging.getLogger()


class ParsedCertFile(object):

    def __init__(self, file):
        LOG.info("Parsing cert file \"%s\".", file)
