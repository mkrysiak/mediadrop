# This file is a part of MediaDrop (http://www.mediadrop.net),
# Copyright 2009-2015 MediaDrop contributors
# For the exact contribution history, see the git revision log.
# The source code contained in this file is licensed under the GPLv3 or
# (at your option) any later version.
# See LICENSE.txt in the main project directory, for more information.

from mediadrop.lib.storage.api import *

from mediadrop.lib.storage.localfiles import LocalFileStorage
from mediadrop.lib.storage.remoteurls import RemoteURLStorage
from mediadrop.lib.storage.swift import SwiftStorage
from mediadrop.lib.storage.ftp import FTPStorage
from mediadrop.lib.storage.youtube import YoutubeStorage
from mediadrop.lib.storage.vimeo import VimeoStorage
from mediadrop.lib.storage.bliptv import BlipTVStorage
from mediadrop.lib.storage.googlevideo import GoogleVideoStorage
from mediadrop.lib.storage.dailymotion import DailyMotionStorage

# provide a unified API, everything storage-related should be available from
# this module
from mediadrop.lib.uri import StorageURI

