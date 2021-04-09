from functools import wraps
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('logfile.log')
formatter = logging.Formatter('%(levelname)s: %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

class CustomAdaptor(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return '[%s %x] %s' % (self.extra['object_class'], self.extra['object_id'], msg), kwargs

def objectID(init):
    @wraps(init)
    def logged_init(self, *args, **kwargs):
        init(self, *args, **kwargs)

        self._logging_adapter = CustomAdaptor(logging.getLogger(), {'object_class': type(self).__name__,
                                                                    'object_id': logged_init.new_id})

        logged_init.new_id += 1
        self._logging_adapter.info('Initialized')

    logged_init.new_id = 0
    return logged_init


def node_log(lambda_message, level = "info", pass_result = False):
    def logging_decorator(function):
        @wraps(function)
        def logged_function(self, *args, **kwargs):
            if level == "debug":
                logger = self._logging_adapter.debug
            if level == "warning":
                logger = self._logging_adapter.warning
            if level == "error":
                logger = self._logging_adapter.error
            if level == "critical":
                logger = self._logging_adapter.critical
            else:
                logger = self._logging_adapter.info

            result = function(self, *args, **kwargs)
            if pass_result:
                logger(lambda_message(self, result, *args, **kwargs))
            else:
                logger(lambda_message(self, *args, **kwargs))

            return result
        return logged_function
    return logging_decorator
