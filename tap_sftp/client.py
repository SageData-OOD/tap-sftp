import io
import os
import socket
import backoff
import paramiko
import pytz
import re
import singer
import stat
from ssl import SSLContext
import gzip
import zipfile
from ftplib import FTP_TLS, all_errors
from datetime import datetime
from paramiko.ssh_exception import AuthenticationException, SSHException

# set default timeout to 300 seconds
REQUEST_TIMEOUT = 300

LOGGER = singer.get_logger()

class SFTPConnection():
    def __init__(self, host, username, password=None, private_key_file=None, port=None, timeout=REQUEST_TIMEOUT):
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port) or 22
        self.__active_connection = False
        self.key = None
        if private_key_file:
            key_path = os.path.expanduser(private_key_file)
            self.key = paramiko.RSAKey.from_private_key_file(key_path)

        if timeout and float(timeout):
            # set the request timeout for the requests
            # if value is 0,"0", "" or None then it will set default to default to 300.0 seconds if not passed in config.
            self.request_timeout = float(timeout)
        else:
            # set the default timeout of 300 seconds
            self.request_timeout = REQUEST_TIMEOUT

    def handle_backoff(details):
        LOGGER.warn("SSH Connection closed unexpectedly. Waiting {wait} seconds and retrying...".format(**details))

    # If connection is snapped during connect flow, retry up to a
    # minute for SSH connection to succeed. 2^6 + 2^5 + ...
    @backoff.on_exception(backoff.expo,
                          (EOFError),
                          max_tries=6,
                          on_backoff=handle_backoff,
                          jitter=None,
                          factor=2)
    def __try_connect(self):
        if not self.__active_connection:
            try:
                self.transport = paramiko.Transport((self.host, self.port))
                self.transport.use_compression(True)
                self.transport.connect(username = self.username, password = self.password, hostkey = None, pkey = self.key)
                self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            except (AuthenticationException, SSHException) as ex:
                self.transport.close()
                self.transport = paramiko.Transport((self.host, self.port))
                self.transport.use_compression(True)
                self.transport.connect(username= self.username, password = self.password, hostkey = None, pkey = None)
                self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            self.__active_connection = True
            # get 'socket' to set the timeout
            socket = self.sftp.get_channel()
            # set request timeout
            socket.settimeout(self.request_timeout)

    @property
    def sftp(self):
        self.__try_connect()
        return self.__sftp

    @sftp.setter
    def sftp(self, sftp):
        self.__sftp = sftp

    def __enter__(self):
        self.__try_connect()
        return self

    def __del__(self):
        """ Clean up the socket when this class gets garbage collected. """
        self.close()

    def __exit__(self):
        """ Clean up the socket when this class gets garbage collected. """
        self.close()

    def close(self):
        if self.__active_connection:
            self.sftp.close()
            self.transport.close()
            self.__active_connection = False

    # backoff for 60 seconds as there is possibility the request will backoff again in 'discover.get_schema'
    @backoff.on_exception(backoff.constant,
                          (socket.timeout),
                          max_time=60,
                          interval=10,
                          jitter=None)
    def get_files_by_prefix(self, prefix):
        """
        Accesses the underlying file system and gets all files that match "prefix", in this case, a directory path.

        Returns a list of filepaths from the root.
        """
        files = []

        if prefix is None or prefix == '':
            prefix = '.'

        try:
            result = self.sftp.listdir_attr(prefix)
        except FileNotFoundError as e:
            raise Exception("Directory '{}' does not exist".format(prefix)) from e

        is_empty = lambda a: a.st_size == 0
        is_directory = lambda a: stat.S_ISDIR(a.st_mode)
        for file_attr in result:
            # NB: This only looks at the immediate level beneath the prefix directory
            if is_directory(file_attr):
                files += self.get_files_by_prefix(prefix + '/' + file_attr.filename)
            else:
                if is_empty(file_attr):
                    continue

                last_modified = file_attr.st_mtime
                if last_modified is None:
                    LOGGER.warning("Cannot read m_time for file %s, defaulting to current epoch time",
                                   os.path.join(prefix, file_attr.filename))
                    last_modified = datetime.utcnow().timestamp()

                # NB: SFTP specifies path characters to be '/'
                #     https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-6
                files.append({"filepath": prefix + '/' + file_attr.filename,
                              "last_modified": datetime.utcfromtimestamp(last_modified).replace(tzinfo=pytz.UTC)})

        return files

    def get_files(self, prefix, search_pattern, modified_since=None):
        files = self.get_files_by_prefix(prefix)
        if files:
            LOGGER.info('Found %s files in "%s"', len(files), prefix)
        else:
            LOGGER.warning('Found no files on specified SFTP server at "%s"', prefix)

        matching_files = self.get_files_matching_pattern(files, search_pattern)

        if matching_files:
            LOGGER.info('Found %s files in "%s" matching "%s"', len(matching_files), prefix, search_pattern)
        else:
            LOGGER.warning('Found no files on specified SFTP server at "%s" matching "%s"', prefix, search_pattern)

        for f in matching_files:
            LOGGER.info("Found file: %s", f['filepath'])

        if modified_since is not None:
            matching_files = [f for f in matching_files if f["last_modified"] > modified_since]

        # sort files in increasing order of "last_modified"
        sorted_files = sorted(matching_files, key=lambda x: (x['last_modified']).timestamp())
        return sorted_files

    # retry 5 times for timeout error
    @backoff.on_exception(backoff.expo,
                          (socket.timeout),
                          max_tries=5,
                          factor=2)
    def get_file_handle(self, f):
        """ Takes a file dict {"filepath": "...", "last_modified": "..."}
        -> returns a handle to the file.
        -> raises error with appropriate logger message """
        try:
            return self.sftp.open(f["filepath"], 'rb')
        except OSError as e:
            if "Permission denied" in str(e):
                LOGGER.warn("Skipping %s file because you do not have enough permissions.", f["filepath"])
            else:
                LOGGER.warn("Skipping %s file because it is unable to be read.", f["filepath"])
            raise

    def get_files_matching_pattern(self, files, pattern):
        """ Takes a file dict {"filepath": "...", "last_modified": "..."} and a regex pattern string, and returns files matching that pattern. """
        matcher = re.compile(pattern)
        return [f for f in files if matcher.search(f["filepath"])]


class FTPSConnection:
    def __init__(self, host, username, password=None, private_key_file=None, certfile=None, port=None,
                 timeout=REQUEST_TIMEOUT):
        self.host = host
        self.username = username
        self.password = password
        self.keyfile = private_key_file
        self.certfile = certfile
        self.port = int(port) or 21
        self.__active_connection = False
        self.key = None

        if timeout and float(timeout):
            # set the request timeout for the requests
            # if value is 0,"0", "" or None then it will set default to default to 300.0 seconds if not passed in config.
            self.request_timeout = float(timeout)
        else:
            # set the default timeout of 300 seconds
            self.request_timeout = REQUEST_TIMEOUT

    def handle_backoff(details):
        LOGGER.warn("Connection closed unexpectedly. Waiting {wait} seconds and retrying...".format(**details))

    @backoff.on_exception(backoff.expo,
                          (EOFError),
                          max_tries=6,
                          on_backoff=handle_backoff,
                          jitter=None,
                          factor=2)
    def __try_connect(self):
        if not self.__active_connection:
            self.ftps_tls = FTP_TLS(keyfile=self.keyfile, certfile=self.certfile, timeout=self.request_timeout)
            self.ftps_tls.connect(self.host, port=self.port)
            self.ftps_tls.login(user=self.username, passwd=self.password)
            self.ftps_tls.prot_p()

            self.ftps = self.ftps_tls
            self.__active_connection = True

    @property
    def ftps(self):
        self.__try_connect()
        return self.__ftps

    @ftps.setter
    def ftps(self, val):
        self.__ftps = val

    def __enter__(self):
        self.__try_connect()
        return self

    def __del__(self):
        """ Clean up the socket when this class gets garbage collected. """
        self.close()

    def __exit__(self):
        """ Clean up the socket when this class gets garbage collected. """
        self.close()

    def close(self):
        if self.__active_connection:
            self.__active_connection = False
            self.ftps.close()

    # backoff for 60 seconds as there is possibility the request will backoff again in 'discover.get_schema'
    @backoff.on_exception(backoff.constant,
                          (socket.timeout),
                          max_time=60,
                          interval=10,
                          jitter=None)
    def get_files_by_prefix(self, prefix):
        """
        Accesses the underlying file system and gets all files that match "prefix", in this case, a directory path.

        Returns a list of filepaths from the root.
        """
        files = []

        if prefix is None or prefix == '':
            prefix = '.'

        try:
            result = self.ftps.mlsd(path=prefix)
        except FileNotFoundError as e:
            raise Exception("Directory '{}' does not exist".format(prefix)) from e

        is_empty = lambda a: a["size"] == "0"
        is_directory = lambda a: a["type"] == "dir"
        for filename, fact in result:
            # NB: This only looks at the immediate level beneath the prefix directory
            if is_directory(fact):
                files += self.get_files_by_prefix(prefix + '/' + filename)
            else:
                if is_empty(fact):
                    continue

                last_modified = fact["modify"]
                if last_modified is None:
                    LOGGER.warning("Cannot read m_time for file %s, defaulting to current epoch time",
                                   os.path.join(prefix, filename))
                    last_modified = datetime.utcnow().timestamp()
                    last_modified = datetime.utcfromtimestamp(last_modified).replace(tzinfo=pytz.UTC)
                else:
                    last_modified = datetime.strptime(last_modified, "%Y%m%d%H%M%S.%f").replace(tzinfo=pytz.UTC)

                # NB: SFTP specifies path characters to be '/'
                #     https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-6
                files.append({"filepath": prefix + '/' + filename,
                              "last_modified": last_modified})

        return files

    def get_files(self, prefix, search_pattern, modified_since=None):
        files = self.get_files_by_prefix(prefix)
        if files:
            LOGGER.info('Found %s files in "%s"', len(files), prefix)
        else:
            LOGGER.warning('Found no files on specified SFTP server at "%s"', prefix)

        matching_files = self.get_files_matching_pattern(files, search_pattern)

        if matching_files:
            LOGGER.info('Found %s files in "%s" matching "%s"', len(matching_files), prefix, search_pattern)
        else:
            LOGGER.warning('Found no files on specified SFTP server at "%s" matching "%s"', prefix, search_pattern)

        for f in matching_files:
            LOGGER.info("Found file: %s", f['filepath'])

        if modified_since is not None:
            matching_files = [f for f in matching_files if f["last_modified"] > modified_since]

        # sort files in increasing order of "last_modified"
        sorted_files = sorted(matching_files, key=lambda x: (x['last_modified']).timestamp())
        return sorted_files

    # retry 5 times for timeout error
    @backoff.on_exception(backoff.expo,
                          (socket.timeout),
                          max_tries=5,
                          factor=2)
    def get_file_handle(self, f):
        """ Takes a file dict {"filepath": "...", "last_modified": "..."}
        -> returns a handle to the file.
        -> raises error with appropriate logger message """
        try:
            iter_ = []
            self.ftps.retrlines(f'RETR {f["filepath"]}', callback=lambda data: iter_.append(data.encode("utf-8")))
            return iter_
        except OSError as e:
            if "Permission denied" in str(e):
                LOGGER.warn("Skipping %s file because you do not have enough permissions.", f["filepath"])
            else:
                LOGGER.warn("Skipping %s file because it is unable to be read.", f["filepath"])
            raise

    def get_files_matching_pattern(self, files, pattern):
        """ Takes a file dict {"filepath": "...", "last_modified": "..."} and a regex pattern string, and returns files matching that pattern. """
        matcher = re.compile(pattern)
        return [f for f in files if matcher.search(f["filepath"])]


def connection(config):
    protocol = config.get("protocol")
    if protocol == "FTPS":
        return FTPSConnection(config['host'],
                              config['username'],
                              password=config.get('password'),
                              private_key_file=config.get('private_key_file'),
                              certfile=config.get('certfile'),
                              port=config.get('port'),
                              timeout=config.get('request_timeout'))
    elif protocol == "SFTP":
        return SFTPConnection(config['host'],
                              config['username'],
                              password=config.get('password'),
                              private_key_file=config.get('private_key_file'),
                              port=config.get('port'),
                              timeout=config.get('request_timeout'))
    else:
        raise Exception("protocol %s is not supported. Supported protocols: ['SFTP', 'FTPS']", protocol)
