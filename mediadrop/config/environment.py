# This file is a part of MediaDrop (http://www.mediadrop.net),
# Copyright 2009-2015 MediaDrop contributors
# For the exact contribution history, see the git revision log.
# The source code contained in this file is licensed under the GPLv3 or
# (at your option) any later version.
# See LICENSE.txt in the main project directory, for more information.
"""Pylons environment configuration"""

import os

from formencode.api import get_localedir as get_formencode_localedir
from genshi.filters.i18n import Translator
import pylons
from pylons.configuration import PylonsConfig
from sqlalchemy import engine_from_config

from mediadrop.lib.app_globals import Globals
import mediadrop.lib.helpers

from mediadrop.config.routing import create_mapper, add_routes
from mediadrop.lib.templating import TemplateLoader
from mediadrop.model import Media, Podcast, init_model
from mediadrop.plugin import PluginManager, events

def load_environment(global_conf, app_conf):
    """Configure the Pylons environment via the ``pylons.config`` object"""
    config = PylonsConfig()

    # Pylons paths
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = dict(root=root,
                 controllers=os.path.join(root, 'controllers'),
                 static_files=os.path.join(root, 'public'),
                 templates=[os.path.join(root, 'templates')])

    # Initialize config with the basic options
    config.init_app(global_conf, app_conf, package='mediadrop', paths=paths)
    env_dir = os.path.normpath(os.path.join(config['media_dir'], '..'))
    config.setdefault('env_dir', env_dir)

    # Initialize the plugin manager to load all active plugins
    plugin_mgr = PluginManager(config)

    mapper = create_mapper(config, plugin_mgr.controller_scan)
    events.Environment.before_route_setup(mapper)
    add_routes(mapper)
    events.Environment.after_route_setup(mapper)
    config['routes.map'] = mapper
    globals_ = Globals(config)
    globals_.plugin_mgr = plugin_mgr
    globals_.events = events
    config['pylons.app_globals'] = globals_
    config['pylons.h'] = mediadrop.lib.helpers

    # Setup cache object as early as possible
    pylons.cache._push_object(globals_.cache)

    i18n_env_dir = os.path.join(config['env_dir'], 'i18n')
    config['locale_dirs'] = plugin_mgr.locale_dirs()
    config['locale_dirs'].update({
        'mediadrop': (os.path.join(root, 'i18n'), i18n_env_dir),
        'FormEncode': (get_formencode_localedir(), i18n_env_dir),
    })

    def enable_i18n_for_template(template):
        translations = Translator(pylons.translator)
        translations.setup(template)

    # Create the Genshi TemplateLoader
    globals_.genshi_loader = TemplateLoader(
        search_path=paths['templates'] + plugin_mgr.template_loaders(),
        auto_reload=True,
        max_cache_size=100,
        callback=enable_i18n_for_template,
    )

    #For Heroku, read DATABASE_URL from the environment
    database_url = os.environ.get("DATABASE_URL", False)
    if database_url:
        config['sqlalchemy.url'] = database_url

    # Setup the SQLAlchemy database engine
    engine = engine_from_config(config, 'sqlalchemy.')
    init_model(engine, config.get('db_table_prefix', None))
    events.Environment.init_model()

    # CONFIGURATION OPTIONS HERE (note: all config options will override
    #                                   any Pylons config options)

    # TODO: Move as many of these custom options into an .ini file, or at least
    #       to somewhere more friendly.

    # TODO: Rework templates not to rely on this line:
    #       See docstring in pylons.configuration.PylonsConfig for details.
    config['pylons.strict_tmpl_context'] = False

    config['thumb_sizes'] = { # the dimensions (in pixels) to scale thumbnails
        Media._thumb_dir: {
            's': (128,  72),
            'm': (160,  90),
            'l': (560, 315),
        },
        Podcast._thumb_dir: {
            's': (128, 128),
            'm': (160, 160),
            'l': (600, 600),
        },
    }

    # For Heroku, read Swift configuration from the environment
    swift_auth = os.environ.get("SWIFT_AUTH", None)
    swift_container = os.environ.get("SWIFT_CONTAINER", None)
    swift_key = os.environ.get("SWIFT_KEY", None)
    swift_user = os.environ.get("SWIFT_USER", None)

    if swift_auth is not None:
        config['swift_auth'] = swift_auth
    if swift_container is not None:
        config['swift_container'] = swift_container
    if swift_key is not None:
        config['swift_key'] = swift_key
    if swift_user is not None:
        config['swift_user'] = swift_user

    ldap_url = os.environ.get("LDAP_URL", None)
    ldap_binddn = os.environ.get("LDAP_BINDDN", None)
    ldap_pw = os.environ.get("LDAP_PW", None)
    ldap_base = os.environ.get("LDAP_BASE", None)

    if ldap_url is not None:
        config['ldap_url'] = ldap_url
    if ldap_binddn is not None:
        config['ldap_binddn'] = ldap_binddn
    if ldap_pw is not None:
        config['ldap_pw'] = ldap_pw
    if ldap_base is not None:
        config['ldap_base'] = ldap_base

    # END CUSTOM CONFIGURATION OPTIONS

    events.Environment.loaded(config)

    return config
