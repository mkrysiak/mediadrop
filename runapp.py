import os

from paste.deploy import loadapp
from paste import httpserver
from configobj import ConfigObj


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    CONFIG_FILE_PATH = 'development.ini'

    app = loadapp('config:development.ini', relative_to='.')
    httpserver.serve(app, host='0.0.0.0', port=port)

