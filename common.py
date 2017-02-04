import logging
import coloredlogs

size_40MB = 41943328

class Logger:

    LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR']

    def __init__(self, module_name, level):
        #coloredlogs.install(level = 'WARNING')
        # coloredlogs.install(level = 'DEBUG')
        #coloredlogs.install(level = 'INFO')
        coloredlogs.install(level = level)
        self.__logger = logging.getLogger(module_name)

    def debug(self, log_info):
        self.__logger.debug(log_info)

    def info(self, log_info):
        self.__logger.info(log_info)
    
    def warning(self, log_info):
        self.__logger.warning(log_info)
    
    def error(self, log_info):
        self.__logger.error(log_info)

# if __name__ == '__main__':
#     logger = Logger('Test', Logger.LEVELS[0])
#     logger.debug('Test')
#     logger.error('Test')
