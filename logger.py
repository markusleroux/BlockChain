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
    # add an object ID to an object, which can be used to identify it on the network
    @wraps(init)
    def logged_init(self, *args, **kwargs):
        init(self, *args, **kwargs)

        self._logging_adapter = CustomAdaptor(logging.getLogger(), {'object_class': type(self).__name__,
                                                                    'object_id': logged_init.new_id})

        logged_init.new_id += 1
        self._logging_adapter.info('Initialized')

    logged_init.new_id = 0
    return logged_init


def node(lambda_message, level = "info", pass_result = False):
    """Constructs a decorator for logging a message, using the lambda
    to pull in information to include in the log from the arguments
    of the call.

    Arguments
    --------
    lambda_message : *args -> **kwargs -> str
        The message to write to the logs

    level : "debug" | "warning" | "error" | "critical" | "info"
        The level to associate with the log
    
    pass_result : bool
        Whether to pass the result to the logger ( if the result
        is passed to the logger, the log is constructed after
        the function is called, and will not be constructed if
        the function fails )


    """
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

            if pass_result:
                result = function(self, *args, **kwargs)
                logger(lambda_message(self, result, *args, **kwargs))
            else:
                logger(lambda_message(self, *args, **kwargs))
                result = function(self, *args, **kwargs)

            return result
        return logged_function
    return logging_decorator
