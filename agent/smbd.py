from impacket import smbserver
from impacket.smb3structs import *
import os
import configparser
import logging
import time


# Add the FILE_ATTRIBUTE_REPARSE_POINT constant
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

class CustomSMBServer(smbserver.SMBSERVER):
    def __init__(self, listenAddress='0.0.0.0', listenPort=1445):
        # Set up logging
        logging.basicConfig(format='%(asctime)s - %(message)s',
                            level=logging.DEBUG)


        # Initialize config
        self.__smbConfig = configparser.ConfigParser()
        self.__smbConfig.add_section('global')
        self.__smbConfig.set('global', 'server_name', 'server_name')
        self.__smbConfig.set('global', 'server_os', 'UNIX')
        self.__smbConfig.set('global', 'server_domain', 'WORKGROUP')
        self.__smbConfig.set('global', 'log_file', 'None')
        self.__smbConfig.set('global', 'credentials_file', '')
        self.__smbConfig.set('global', 'challenge', "A" * 16)
        self.__smbConfig.set('global', 'rpc_apis', 'yes')
        self.__smbConfig.set('global', 'SMB2Support', 'yes')


        # Add RCE share
        self.__smbConfig.add_section('RCE')
        self.__smbConfig.set('RCE', 'comment', 'Testing share')
        self.__smbConfig.set('RCE', 'read only', 'no')
        self.__smbConfig.set('RCE', 'share type', '0')
        self.__smbConfig.set('RCE', 'path', '/RCE')


        # Add IPC$
        self.__smbConfig.add_section('IPC$')
        self.__smbConfig.set('IPC$', 'comment', '')
        self.__smbConfig.set('IPC$', 'read only', 'yes')
        self.__smbConfig.set('IPC$', 'share type', '3')
        self.__smbConfig.set('IPC$', 'path', '')

        # Call parent's init
        smbserver.SMBSERVER.__init__(self, (listenAddress, listenPort), config_parser=self.__smbConfig)

        self._log = logging.getLogger('impacket.smbserver')

        self.processConfigFile()

def main():
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.DEBUG)
    logger = logging.getLogger()
    server = CustomSMBServer()
    logger.info("[*] Creating server...")
    try:
        logger.info("[*] Server is starting")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[*] Stopping server")
        server.server_close()

if __name__ == '__main__':
    main()
