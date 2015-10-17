# This file is a part of MediaDrop (http://www.mediadrop.net),
# Copyright 2009-2015 MediaDrop contributors
# For the exact contribution history, see the git revision log.
# The source code contained in this file is licensed under the GPLv3 or
# (at your option) any later version.
# See LICENSE.txt in the main project directory, for more information.

import logging
import time
import os

#from ftplib import FTP, all_errors as ftp_errors
import swiftclient
from urllib2 import HTTPError, urlopen

from formencode import Invalid

from pylons import config

from mediadrop.lib.compat import sha1
from mediadrop.lib.i18n import N_, _
from mediadrop.lib.storage.api import FileStorageEngine, safe_file_name
from mediadrop.lib.uri import StorageURI

log = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

class SwiftUploadError(Invalid):
    pass

class SwiftStorage(FileStorageEngine):

    engine_type = u'SwiftStorage'
    """A uniquely identifying string for each StorageEngine implementation."""

    default_name = N_(u'Swift Storage')
    """A user-friendly display name that identifies this StorageEngine."""

    """Storage Engines that should :meth:`parse` after this class has.

    This is a list of StorageEngine class objects which is used to
    perform a topological sort of engines. See :func:`sort_engines`
    and :func:`add_new_media_file`.
    """

    def store(self, media_file, file=None, url=None, meta=None):
        """Store the given file or URL and return a unique identifier for it.

        :type media_file: :class:`~mediadrop.model.media.MediaFile`
        :param media_file: The associated media file object.

        :type file: :class:`cgi.FieldStorage` or None
        :param file: A freshly uploaded file object.

        :type url: unicode or None
        :param url: A remote URL string.

        :type meta: dict
        :param meta: The metadata returned by :meth:`parse`.

        :rtype: unicode or None
        :returns: The unique ID string. Return None if not generating it here.

        :raises SwiftUploadError: If storing the file fails.

        """
        file_name = safe_file_name(media_file, file.filename)

        swift = self._connect()

        try:
            swift.put_object(config['swift_container'], file_name, file.file)
            swift.close()
        except Exception, e:
            log.exception(e)
            swift.close()
            msg = _('Could not upload the file to your Swift server: %s')\
                % e.message
            raise SwiftUploadError(msg, None, None)

        return file_name

    def delete(self, unique_id):
        """Delete the stored file represented by the given unique ID.

        :type unique_id: unicode
        :param unique_id: The identifying string for this file.

        :rtype: boolean
        :returns: True if successful, False if an error occurred.

        """
        swift = self._connect()
        try:
            swift.delete_object(config['swift_container'], unique_id)
            swift.close()
            return True
        except Exception, e:
            log.exception(e)
            swift.close()
            return False

    def get_uris(self, media_file):
        """Return a list of URIs from which the stored file can be accessed.

        :type media_file: :class:`~mediadrop.model.media.MediaFile`
        :param media_file: The associated media file object.
        :rtype: list
        :returns: All :class:`StorageURI` tuples for this file.

        """
        try:
            swift = self._connect()
            swift_download_url = os.path.join(swift.get_auth()[0], config['swift_container'])
            swift.close()
        except Exception, e:
            log.exception(e)
            swift.close()

        uid = media_file.unique_id
        url = os.path.join(swift_download_url, uid)
        uris = [StorageURI(media_file, 'http', url, None)]

        return uris

    def _connect(self):
        """Open a connection to the FTP server."""

        swift_auth = config['swift_auth']
        swift_key = config['swift_key']
        swift_user = config['swift_user']

        return swiftclient.client.Connection(auth_version='1',
                                             user = swift_user,
                                             key = swift_key,
                                             authurl = swift_auth)

        

    def _verify_upload_integrity(self, file, file_url):
        """Download the given file from the URL and compare the SHA1s.

        :type file: :class:`cgi.FieldStorage`
        :param file: A freshly uploaded file object, that has just been
            sent to the FTP server.

        :type file_url: str
        :param file_url: A publicly accessible URL where the uploaded file
            can be downloaded.

        :returns: `True` if the integrity check succeeds or is disabled.

        :raises FTPUploadError: If the file cannot be downloaded after
            the max number of retries, or if the the downloaded file
            doesn't match the original.

        """
        max_tries = int(self._data[SWIFT_MAX_INTEGRITY_RETRIES])
        if max_tries < 1:
            return True

        file.seek(0)
        orig_hash = sha1(file.read()).hexdigest()

        # Try to download the file. Increase the number of retries, or the
        # timeout duration, if the server is particularly slow.
        # eg: Akamai usually takes 3-15 seconds to make an uploaded file
        #     available over HTTP.
        for i in xrange(max_tries):
            try:
                temp_file = urlopen(file_url)
                dl_hash = sha1(temp_file.read()).hexdigest()
                temp_file.close()
            except HTTPError, http_err:
                # Don't raise the exception now, wait until all attempts fail
                time.sleep(3)
            else:
                # If the downloaded file matches, success! Otherwise, we can
                # be pretty sure that it got corrupted during FTP transfer.
                if orig_hash == dl_hash:
                    return True
                else:
                    msg = _('The file transferred to your FTP server is '\
                            'corrupted. Please try again.')
                    raise SwiftUploadError(msg, None, None)

        # Raise the exception from the last download attempt
        msg = _('Could not download the file from your FTP server: %s')\
            % http_err.message
        raise SwiftUploadError(msg, None, None)

FileStorageEngine.register(SwiftStorage)
