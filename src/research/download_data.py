import os
import gzip
import stat
import shutil
import logging
import zipfile
import tarfile
import argparse
import subprocess
import json
from pathlib import Path

from urllib.parse import urlparse


# https://github.com/vinta/awesome-python/tree/master
BENIGN_REPO_URLS = [
    "http://github.com/pymatting/pymatting",
    "http://python-xy.github.io/",
    "https://github.com/0rpc/zerorpc-python",
    "https://github.com/aaugustin/websockets",
    "https://github.com/abhiTronix/vidgear",
    "https://github.com/aboSamoor/polyglot",
    "https://github.com/ahupp/python-magic",
    "https://github.com/aio-libs/aiohttp.git",
    "https://github.com/aizvorski/scikit-video",
    "https://github.com/ajenti/ajenti",
    "https://github.com/alecthomas/voluptuous",
    "https://github.com/Alir3z4/html2text",
    "https://github.com/altair-viz/altair",
    "https://github.com/amitt001/delegator.py",
    "https://github.com/amoffat/sh",
    "https://github.com/andialbrecht/sqlparse",
    "https://github.com/ansible/ansible",
    "https://github.com/apache/spark",
    "https://github.com/arrow-py/arrow",
    "https://github.com/asweigart/pyautogui",
    "https://github.com/AtsushiSakai/PythonRobotics",
    "https://github.com/aws/aws-cli.git",
    "https://github.com/aws/aws-sam-cli.git",
    "https://github.com/aws/aws-sdk-pandas",
    "https://github.com/aws/deep-learning-containers.git",
    "https://github.com/aws/serverless-application-model.git",
    "https://github.com/Azure/Azure-Sentinel.git",
    "https://github.com/bbangert/beaker",
    "https://github.com/beetbox/audioread",
    "https://github.com/beetbox/beets",
    "https://github.com/benedekrozemberczki/karateclub",
    "https://github.com/benfred/implicit",
    "https://github.com/benfred/py-spy",
    "https://github.com/benhamner/Metrics",
    "https://github.com/benoitc/gunicorn",
    "https://github.com/bloomberg/bqplot",
    "https://github.com/Bogdanp/dramatiq",
    "https://github.com/bokeh/bokeh",
    "https://github.com/boppreh/keyboard",
    "https://github.com/boppreh/mouse",
    "https://github.com/borgbackup/borg",
    "https://github.com/boto/boto3.git",
    "https://github.com/boto/boto3",
    "https://github.com/boto/botocore.git",
    "https://github.com/bpython/bpython",
    "https://github.com/buildout/buildout",
    "https://github.com/buriy/python-readability",
    "https://github.com/burnash/gspread",
    "https://github.com/canonical/cloud-init",
    "https://github.com/carlosescri/DottedDict",
    "https://github.com/cdgriffith/Box",
    "https://github.com/chapmanb/bcbb",
    "https://github.com/chapmanb/bcbio-nextgen",
    "https://github.com/chardet/chardet",
    "https://github.com/chriskiehl/Gooey",
    "https://github.com/ChrisKnott/Eel",
    "https://github.com/ChristosChristofidis/awesome-deep-learning",
    "https://github.com/CleanCut/green",
    "https://github.com/clips/pattern",
    "https://github.com/cobrateam/splinter",
    "https://github.com/codeinthehole/purl",
    "https://github.com/codelucas/newspaper",
    "https://github.com/coleifer/huey",
    "https://github.com/coleifer/micawber",
    "https://github.com/coleifer/peewee",
    "https://github.com/conda/conda/",
    "https://github.com/cookiecutter/cookiecutter",
    "https://github.com/copier-org/copier",
    "https://github.com/Cornices/cornice",
    "https://github.com/crossbario/autobahn-python",
    "https://github.com/cython/cython",
    "https://github.com/dabeaz/ply",
    "https://github.com/dahlia/awesome-sqlalchemy",
    "https://github.com/dashingsoft/pyarmor",
    "https://github.com/dask/dask",
    "https://github.com/datafolklabs/cement",
    "https://github.com/datastax/python-driver",
    "https://github.com/dateutil/dateutil",
    "https://github.com/davidaurelio/hashids-python",
    "https://github.com/daviddrysdale/python-phonenumbers",
    "https://github.com/davidhalter/jedi-vim",
    "https://github.com/davidhalter/jedi",
    "https://github.com/dbader/schedule",
    "https://github.com/dbcli/litecli",
    "https://github.com/dbcli/mycli",
    "https://github.com/dbcli/pgcli",
    "https://github.com/deanmalmgren/textract",
    "https://github.com/Delgan/loguru",
    "https://github.com/derek73/python-nameparser",
    "https://github.com/devpi/devpi",
    "https://github.com/devsnd/tinytag",
    "https://github.com/dfunckt/django-rules",
    "https://github.com/dhamaniasad/awesome-postgres",
    "https://github.com/DiffSK/configobj",
    "https://github.com/dimka665/awesome-slugify",
    "https://github.com/django-cache-machine/django-cache-machine",
    "https://github.com/django-compressor/django-compressor",
    "https://github.com/django-guardian/django-guardian",
    "https://github.com/django-haystack/django-haystack",
    "https://github.com/django-haystack/pysolr",
    "https://github.com/django-tastypie/django-tastypie",
    "https://github.com/django/channels",
    "https://github.com/django/daphne",
    "https://github.com/django/django.git",
    "https://github.com/django/django",
    "https://github.com/DLR-RM/BlenderProc.git",
    "https://github.com/DLR-RM/stable-baselines3",
    "https://github.com/dmlc/xgboost",
    "https://github.com/DmytroLitvinov/awesome-flake8-extensions",
    "https://github.com/dpkp/kafka-python",
    "https://github.com/dry-python/returns",
    "https://github.com/dylanaraps/pywal",
    "https://github.com/elapouya/python-docx-template",
    "https://github.com/elastic/elasticsearch-dsl-py",
    "https://github.com/eliben/pycparser.git",
    "https://github.com/eliben/pyelftools",
    "https://github.com/ellisonleao/pyshorteners",
    "https://github.com/emcconville/wand",
    "https://github.com/emirozer/fake2db",
    "https://github.com/encode/django-rest-framework",
    "https://github.com/encode/httpx",
    "https://github.com/encode/orm",
    "https://github.com/encode/uvicorn",
    "https://github.com/erikrose/more-itertools",
    "https://github.com/errbotio/errbot/",
    "https://github.com/esnme/ultrajson",
    "https://github.com/eventlet/eventlet",
    "https://github.com/evhub/coconut",
    "https://github.com/fabric/fabric",
    "https://github.com/facebook/PathPicker",
    "https://github.com/facebook/pyre-check",
    "https://github.com/facebookresearch/detectron2.git",
    "https://github.com/facebookresearch/fairseq.git",
    "https://github.com/facebookresearch/hydra",
    "https://github.com/facebookresearch/pytext",
    "https://github.com/FactoryBoy/factory_boy",
    "https://github.com/faif/python-patterns",
    "https://github.com/falconry/falcon",
    "https://github.com/fastapi/fastapi.git",
    "https://github.com/feincms/feincms",
    "https://github.com/fengsp/plan",
    "https://github.com/fighting41love/funNLP",
    "https://github.com/flask-admin/flask-admin",
    "https://github.com/flask-api/flask-api",
    "https://github.com/flask-restful/flask-restful",
    "https://github.com/fogleman/Quads",
    "https://github.com/fxsjy/jieba",
    "https://github.com/gabrielfalcao/HTTPretty",
    "https://github.com/gaojiuli/toapi",
    "https://github.com/gawel/pyquery",
    "https://github.com/geopy/geopy",
    "https://github.com/getnikola/nikola",
    "https://github.com/getpelican/pelican",
    "https://github.com/getsentry/responses",
    "https://github.com/getsentry/sentry-python",
    "https://github.com/gevent/gevent",
    "https://github.com/giampaolo/psutil",
    "https://github.com/glamp/bashplotlib",
    "https://github.com/gleitz/howdoi",
    "https://github.com/google/google-api-python-client",
    "https://github.com/google/python-fire",
    "https://github.com/google/python-fire",
    "https://github.com/google/pytype",
    "https://github.com/google/yapf",
    "https://github.com/googleapis/google-api-python-client",
    "https://github.com/gorakhargosh/watchdog",
    "https://github.com/gotcha/ipdb",
    "https://github.com/grantjenks/python-diskcache",
    "https://github.com/grantjenks/python-sortedcontainers",
    "https://github.com/graphql-python/graphene/",
    "https://github.com/gruns/furl",
    "https://github.com/gruns/icecream",
    "https://github.com/guestwalk/libffm",
    "https://github.com/gunnery/gunnery",
    "https://github.com/h2oai/h2o-3",
    "https://github.com/has2k1/plotnine",
    "https://github.com/HBNetwork/python-decouple",
    "https://github.com/hi-primus/optimus",
    "https://github.com/html5lib/html5lib-python",
    "https://github.com/httpie/cli",
    "https://github.com/hugapi/hug",
    "https://github.com/huggingface/transformers.git",
    "https://github.com/humiaozuzu/awesome-flask",
    "https://github.com/HypothesisWorks/hypothesis",
    "https://github.com/ibayer/fastFM",
    "https://github.com/indico/indico",
    "https://github.com/inducer/pudb",
    "https://github.com/Instagram/MonkeyType",
    "https://github.com/ionelmc/python-hunter",
    "https://github.com/ionelmc/python-manhole",
    "https://github.com/IronLanguages/ironpython3",
    "https://github.com/isnowfy/snownlp",
    "https://github.com/istrategylabs/django-wordpress",
    "https://github.com/jab/bidict",
    "https://github.com/JaidedAI/EasyOCR",
    "https://github.com/jaraco/path.py",
    "https://github.com/jazzband/django-debug-toolbar",
    "https://github.com/jazzband/django-oauth-toolkit",
    "https://github.com/jazzband/django-pipeline",
    "https://github.com/jazzband/django-taggit",
    "https://github.com/jazzband/geojson",
    "https://github.com/jazzband/localshop",
    "https://github.com/jazzband/pip-tools",
    "https://github.com/jazzband/tablib",
    "https://github.com/jeffknupp/sandman2",
    "https://github.com/jek/blinker",
    "https://github.com/jendrikseipp/vulture",
    "https://github.com/jet-admin/jet-bridge",
    "https://github.com/jfkirk/tensorrec",
    "https://github.com/jiaaro/pydub",
    "https://github.com/jindaxiang/akshare",
    "https://github.com/jmcnamara/XlsxWriter",
    "https://github.com/JohnLangford/vowpal_wabbit/",
    "https://github.com/joke2k/faker",
    "https://github.com/jonathanslenders/ptpython",
    "https://github.com/jonathanslenders/python-prompt-toolkit",
    "https://github.com/jorgenschaefer/elpy",
    "https://github.com/josephmisiti/awesome-machine-learning#python",
    "https://github.com/josephreisinger/vowpal_porpoise",
    "https://github.com/jpadilla/pyjwt",
    "https://github.com/jschneier/django-storages",
    "https://github.com/justquick/django-activity-stream",
    "https://github.com/keleshev/schema",
    "https://github.com/keon/algorithms",
    "https://github.com/keras-team/keras",
    "https://github.com/keunwoochoi/kapre",
    "https://github.com/kevin1024/vcrpy",
    "https://github.com/kiddouk/redisco",
    "https://github.com/kiwicom/schemathesis",
    "https://github.com/klen/mixer",
    "https://github.com/knipknap/SpiffWorkflow",
    "https://github.com/kootenpv/yagmail",
    "https://github.com/kornia/kornia/",
    "https://github.com/Kozea/pygal",
    "https://github.com/kurtmckee/feedparser",
    "https://github.com/laixintao/iredis",
    "https://github.com/lancopku/pkuseg-python",
    "https://github.com/lektor/lektor",
    "https://github.com/lemire/simdjson",
    "https://github.com/lepture/authlib",
    "https://github.com/lepture/mistune",
    "https://github.com/lericson/pylibmc",
    "https://github.com/libAudioFlux/audioFlux",
    "https://github.com/librosa/librosa",
    "https://github.com/libvips/pyvips",
    "https://github.com/Lightning-AI/pytorch-lightning",
    "https://github.com/lincolnloop/python-qrcode",
    "https://github.com/linkedin/shiv",
    "https://github.com/lk-geimfari/mimesis",
    "https://github.com/locustio/locust",
    "https://github.com/lorien/grab",
    "https://github.com/LuminosoInsight/python-ftfy",
    "https://github.com/lyst/lightfm",
    "https://github.com/maciejkula/spotlight",
    "https://github.com/madmaze/pytesseract",
    "https://github.com/magenta/magenta",
    "https://github.com/MagicStack/uvloop",
    "https://github.com/mahmoud/boltons",
    "https://github.com/mailgun/flanker",
    "https://github.com/Manisso/fsociety",
    "https://github.com/Maratyszcza/PeachPy",
    "https://github.com/markusschanta/awesome-jupyter",
    "https://github.com/marrow/mailer",
    "https://github.com/marshmallow-code/marshmallow",
    "https://github.com/marshmallow-code/webargs",
    "https://github.com/martinblech/xmltodict",
    "https://github.com/martinrusev/imbox",
    "https://github.com/MasoniteFramework/masonite",
    "https://github.com/matplotlib/matplotlib",
    "https://github.com/MechanicalSoup/MechanicalSoup",
    "https://github.com/metawilm/cl-python",
    "https://github.com/mhammond/pywin32",
    "https://github.com/mher/flower",
    "https://github.com/michaelhelmick/lassie",
    "https://github.com/micropython/micropython",
    "https://github.com/microsoft/markitdown.git",
    "https://github.com/Microsoft/PTVS",
    "https://github.com/mindflayer/python-mocket",
    "https://github.com/mindsdb/mindsdb",
    "https://github.com/mingrammer/diagrams",
    "https://github.com/mininet/mininet",
    "https://github.com/miracle2k/flask-assets",
    "https://github.com/miracle2k/webassets",
    "https://github.com/miso-belica/sumy",
    "https://github.com/mitmproxy/pdoc",
    "https://github.com/mitsuhiko/pluginbase",
    "https://github.com/mitsuhiko/unp",
    "https://github.com/mkdocs/mkdocs/",
    "https://github.com/mlflow/mlflow.git",
    "https://github.com/mobolic/facebook-sdk",
    "https://github.com/modoboa/modoboa",
    "https://github.com/moggers87/salmon",
    "https://github.com/mongodb/mongo-python-driver",
    "https://github.com/mongodb/motor",
    "https://github.com/MongoEngine/mongoengine",
    "https://github.com/moses-palmer/pynput",
    "https://github.com/mozilla/bleach",
    "https://github.com/mozilla/unicode-slugify",
    "https://github.com/mozillazg/python-pinyin",
    "https://github.com/mpdavis/python-jose/",
    "https://github.com/mre/awesome-static-analysis",
    "https://github.com/msiemens/tinydb",
    "https://github.com/mstamy2/PyPDF2",
    "https://github.com/mwaskom/seaborn",
    "https://github.com/mymarilyn/clickhouse-driver",
    "https://github.com/napalm-automation/napalm",
    "https://github.com/nficano/python-lambda",
    "https://github.com/nicfit/eyeD3",
    "https://github.com/NicolasHug/Surprise",
    "https://github.com/nose-devs/nose2",
    "https://github.com/noxrepo/pox",
    "https://github.com/nucleic/enaml",
    "https://github.com/numba/numba",
    "https://github.com/numenta/nupic",
    "https://github.com/numpy/numpy.git",
    "https://github.com/nvbn/thefuck",
    "https://github.com/nvdv/vprof",
    "https://github.com/oauthlib/oauthlib",
    "https://github.com/obspy/obspy/wiki/",
    "https://github.com/openai/gym",
    "https://github.com/openembedded/bitbake",
    "https://github.com/openstack/cliff",
    "https://github.com/orsinium/textdistance",
    "https://github.com/ovalhub/pyicu",
    "https://github.com/pallets-eco/flask-debugtoolbar",
    "https://github.com/pallets/click/",
    "https://github.com/pallets/flask.git",
    "https://github.com/pallets/flask",
    "https://github.com/pallets/itsdangerous",
    "https://github.com/pallets/jinja",
    "https://github.com/pallets/markupsafe",
    "https://github.com/pallets/werkzeug",
    "https://github.com/pandas-dev/pandas.git",
    "https://github.com/paramiko/paramiko",
    "https://github.com/Parisson/TimeSide",
    "https://github.com/Parsely/streamparse",
    "https://github.com/patrys/httmock",
    "https://github.com/patx/pickledb",
    "https://github.com/pdfminer/pdfminer.six",
    "https://github.com/pennersr/django-allauth",
    "https://github.com/peterbrittain/asciimatics",
    "https://github.com/PetrochukM/PyTorch-NLP",
    "https://github.com/pgjones/hypercorn",
    "https://github.com/planetopendata/awesome-sqlite",
    "https://github.com/platformio/platformio-core",
    "https://github.com/ponyorm/pony/",
    "https://github.com/prabhupant/python-ds",
    "https://github.com/PrefectHQ/prefect",
    "https://github.com/pricingassistant/mrq",
    "https://github.com/prompt-toolkit/python-prompt-toolkit",
    "https://github.com/psf/black",
    "https://github.com/psf/requests-html",
    "https://github.com/psf/requests.git",
    "https://github.com/psf/requests",
    "https://github.com/psycopg/psycopg",
    "https://github.com/pudo/dataset",
    "https://github.com/pwaller/pyfiglet",
    "https://github.com/py2exe/py2exe",
    "https://github.com/pybee/toga",
    "https://github.com/pybuilder/pybuilder",
    "https://github.com/pyca/cryptography.git",
    "https://github.com/pyca/cryptography",
    "https://github.com/pyca/pynacl",
    "https://github.com/PyCQA/flake8",
    "https://github.com/PyCQA/prospector",
    "https://github.com/pydantic/pydantic",
    "https://github.com/pyenv/pyenv",
    "https://github.com/pyeve/cerberus",
    "https://github.com/pyeve/eve",
    "https://github.com/pyexcel/pyexcel",
    "https://github.com/pyglet/pyglet",
    "https://github.com/pygraphviz/pygraphviz/",
    "https://github.com/pyinfra-dev/pyinfra",
    "https://github.com/pyinstaller/pyinstaller",
    "https://github.com/pyinvoke/invoke",
    "https://github.com/pylint-dev/pylint",
    "https://github.com/Pylons/colander",
    "https://github.com/Pylons/waitress",
    "https://github.com/pymc-devs/pymc3",
    "https://github.com/pymssql/pymssql",
    "https://github.com/PyMySQL/mysqlclient",
    "https://github.com/PyMySQL/PyMySQL",
    "https://github.com/pynamodb/PynamoDB",
    "https://github.com/pypa/bandersnatch/",
    "https://github.com/pypa/setuptools.git",
    "https://github.com/pypa/virtualenv",
    "https://github.com/pypa/warehouse",
    "https://github.com/pyparsing/pyparsing",
    "https://github.com/pyqtgraph/pyqtgraph",
    "https://github.com/PySimpleGUI/PySimpleGUI",
    "https://github.com/pyston/pyston/",
    "https://github.com/python-attrs/attrs",
    "https://github.com/python-excel/xlrd",
    "https://github.com/python-excel/xlwt",
    "https://github.com/python-greenlet/greenlet",
    "https://github.com/python-happybase/happybase",
    "https://github.com/python-jsonschema/jsonschema",
    "https://github.com/python-mode/python-mode",
    "https://github.com/python-openxml/python-docx",
    "https://github.com/python-pillow/Pillow",
    "https://github.com/python-rapidjson/python-rapidjson",
    "https://github.com/python-rope/rope",
    "https://github.com/python-trio/trio",
    "https://github.com/python/cpython.git",
    "https://github.com/python/cpython",
    "https://github.com/python/mypy",
    "https://github.com/python/typeshed",
    "https://github.com/pythonnet/pythonnet",
    "https://github.com/pytoolz/cytoolz/",
    "https://github.com/pytoolz/toolz",
    "https://github.com/pytorch/pytorch.git",
    "https://github.com/pytorch/pytorch",
    "https://github.com/pytransitions/transitions",
    "https://github.com/quantopian/zipline",
    "https://github.com/quodlibet/mutagen",
    "https://github.com/r0x0r/pywebview/",
    "https://github.com/RaRe-Technologies/gensim",
    "https://github.com/ray-project/ray/",
    "https://github.com/RaylockLLC/DearPyGui/",
    "https://github.com/realpython/list-of-python-api-wrappers",
    "https://github.com/redis/redis-py",
    "https://github.com/robinhood/faust",
    "https://github.com/robotframework/robotframework",
    "https://github.com/ronaldoussoren/py2app",
    "https://github.com/rq/rq",
    "https://github.com/rsalmei/alive-progress",
    "https://github.com/ryanmcgrath/twython",
    "https://github.com/s3tools/s3cmd",
    "https://github.com/saffsd/langid.py",
    "https://github.com/saltstack/salt",
    "https://github.com/sanic-org/sanic",
    "https://github.com/scanny/python-pptx",
    "https://github.com/schematics/schematics",
    "https://github.com/scipy/scipy.git",
    "https://github.com/SciTools/cartopy",
    "https://github.com/SCons/scons",
    "https://github.com/scottrogowski/code2flow",
    "https://github.com/scrapy/scrapy",
    "https://github.com/sdispater/orator",
    "https://github.com/sdispater/pendulum",
    "https://github.com/sdispater/poetry",
    "https://github.com/seatgeek/fuzzywuzzy",
    "https://github.com/seatgeek/sixpack",
    "https://github.com/sebastien/cuisine",
    "https://github.com/secdev/scapy",
    "https://github.com/sehmaschine/django-grappelli",
    "https://github.com/selwin/python-user-agents",
    "https://github.com/sergree/matchering",
    "https://github.com/shahraizali/awesome-django",
    "https://github.com/simonw/datasette",
    "https://github.com/simonw/sqlite-utils",
    "https://github.com/sindresorhus/awesome",
    "https://github.com/sirfz/tesserocr",
    "https://github.com/skorokithakis/shortuuid",
    "https://github.com/sloria/doitlive",
    "https://github.com/SmileyChris/django-countries",
    "https://github.com/sorrycc/awesome-javascript#data-visualization",
    "https://github.com/sphinx-doc/sphinx/",
    "https://github.com/spotify/annoy",
    "https://github.com/spotify/luigi",
    "https://github.com/spulec/freezegun",
    "https://github.com/spyder-ide/spyder",
    "https://github.com/sqlalchemy/dogpile.cache",
    "https://github.com/sqlmapproject/sqlmap",
    "https://github.com/stanfordnlp/stanza",
    "https://github.com/statsmodels/statsmodels",
    "https://github.com/stchris/untangle",
    "https://github.com/stephenmcd/hot-redis",
    "https://github.com/streamlit/streamlit",
    "https://github.com/sunainapai/makesite",
    "https://github.com/Suor/django-cacheops",
    "https://github.com/Suor/funcy",
    "https://github.com/Supervisor/supervisor",
    "https://github.com/sympy/sympy",
    "https://github.com/tartley/colorama",
    "https://github.com/tayllan/awesome-algorithms",
    "https://github.com/Tencent/rapidjson",
    "https://github.com/tensorflow/tensorflow.git",
    "https://github.com/tensorflow/tensorflow",
    "https://github.com/tesseract-ocr",
    "https://github.com/Textualize/rich",
    "https://github.com/thauber/django-schedule",
    "https://github.com/TheAlgorithms/Python",
    "https://github.com/Theano/Theano",
    "https://github.com/thumbor/thumbor",
    "https://github.com/tiangolo/fastapi",
    "https://github.com/timofurrer/awesome-asyncio",
    "https://github.com/timofurrer/try",
    "https://github.com/timothycrosley/isort",
    "https://github.com/TkTech/pysimdjson",
    "https://github.com/tmux-python/tmuxp",
    "https://github.com/tmux/tmux",
    "https://github.com/tomerfiliba/rpyc",
    "https://github.com/TomNicholas/Python-for-Scientists",
    "https://github.com/tornadoweb/tornado",
    "https://github.com/tqdm/tqdm",
    "https://github.com/trustedsec/social-engineer-toolkit",
    "https://github.com/tschellenbach/Stream-Framework",
    "https://github.com/twisted/treq",
    "https://github.com/twisted/twisted",
    "https://github.com/tyiannak/pyAudioAnalysis",
    "https://github.com/tylerlaberge/PyPattyrn",
    "https://github.com/typeddjango/awesome-python-typing",
    "https://github.com/un33k/python-slugify",
    "https://github.com/unoconv/unoconv",
    "https://github.com/uralbash/awesome-pyramid",
    "https://github.com/urllib3/urllib3.git",
    "https://github.com/urllib3/urllib3",
    "https://github.com/Valloric/YouCompleteMe",
    "https://github.com/vandersonmota/model_mommy",
    "https://github.com/vinta/awesome-python#restful-api",
    "https://github.com/vinta/pangu.py",
    "https://github.com/vispy/vispy",
    "https://github.com/wagtail/wagtail",
    "https://github.com/waylan/Python-Markdown",
    "https://github.com/web2py/pydal/",
    "https://github.com/WhyNotHugo/python-barcode",
    "https://github.com/wireservice/csvkit",
    "https://github.com/wooey/wooey",
    "https://github.com/worldveil/dejavu",
    "https://github.com/wsvincent/awesome-django",
    "https://github.com/xonsh/xonsh/",
    "https://github.com/yoloseem/awesome-sphinxdoc",
    "https://github.com/ytdl-org/youtube-dl/",
    "https://github.com/zappa/Zappa",
    "https://github.com/ziadoz/awesome-php",
    "https://github.com/zoofIO/flexx",
    "https://github.com/ZoomerAnalytics/xlwings",
    "https://github.com/zopefoundation/ZODB",
    "https://github.com/ztane/python-Levenshtein/",
    "https://winpython.github.io/",
]
DATADOG_MALICIOUS_REPO_URL = (
    "https://github.com/DataDog/malicious-software-packages-dataset.git"
)
MALICIOUS_REPO_URLS = [
    "https://github.com/lxyeternal/pypi_malregistry.git",
    DATADOG_MALICIOUS_REPO_URL,
]
ENCRYPTED_ZIP_PASSWORD = b"infected"  # Password for DataDog encrypted zips

# Sample Rust repositories to ingest
RUST_REPO_URLS = [
    "https://github.com/rust-lang/rust-clippy",
    "https://github.com/serde-rs/serde",
    "https://github.com/tokio-rs/tokio",
]

REPO_CACHE_DIR = ".repo_cache"
BENIGN_REPOS_CACHE_PATH = os.path.join(REPO_CACHE_DIR, "benign_repos")
MALICIOUS_REPOS_CACHE_PATH = os.path.join(REPO_CACHE_DIR, "malicious_repos")
RUST_REPOS_CACHE_PATH = os.path.join(REPO_CACHE_DIR, "rust_repos")

# Load pinned repository configurations
PINNED_REPOS_CONFIG_PATH = (
    Path(__file__).parent.parent.parent / "util" / "pinned_repositories.json"
)
PINNED_REPOS_CONFIG = None


def load_pinned_repositories():
    """Load pinned repository configuration for reproducible training."""
    global PINNED_REPOS_CONFIG
    if PINNED_REPOS_CONFIG is None:
        try:
            if PINNED_REPOS_CONFIG_PATH.exists():
                with open(PINNED_REPOS_CONFIG_PATH, "r") as f:
                    PINNED_REPOS_CONFIG = json.load(f)
                logging.info(
                    f"Loaded pinned repositories configuration with {PINNED_REPOS_CONFIG['metadata']['total_repositories']} repositories"
                )
            else:
                logging.warning(
                    f"Pinned repositories config not found at {PINNED_REPOS_CONFIG_PATH}"
                )
                logging.warning("Falling back to latest commits (non-reproducible)")
                PINNED_REPOS_CONFIG = {}
        except Exception as e:
            logging.error(f"Failed to load pinned repositories config: {e}")
            logging.warning("Falling back to latest commits (non-reproducible)")
            PINNED_REPOS_CONFIG = {}
    return PINNED_REPOS_CONFIG


# Global flag to control pinning behavior
USE_PINNED_COMMITS = True


def get_pinned_commit_for_url(repo_url):
    """Get the pinned commit hash for a repository URL."""
    if not USE_PINNED_COMMITS:
        return None

    config = load_pinned_repositories()

    # Check benign repositories
    benign_repos = config.get("benign_repositories", {})
    if repo_url in benign_repos:
        repo_data = benign_repos[repo_url]
        commit_hash = repo_data.get("commit_hash")
        if commit_hash:
            return commit_hash

    # Check malicious repositories
    malicious_repos = config.get("malicious_repositories", {})
    if repo_url in malicious_repos:
        repo_data = malicious_repos[repo_url]
        commit_hash = repo_data.get("commit_hash")
        if commit_hash:
            return commit_hash

    return None


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(module)s.%(funcName)s] %(message)s",
    handlers=[logging.StreamHandler()],
)


def _get_repo_name_from_url_internal(url):
    try:
        path_part = urlparse(url).path
        repo_name = path_part.strip("/").replace(".git", "")
        return os.path.basename(repo_name)
    except Exception:
        return os.path.basename(url).replace(".git", "")


DATADOG_MALICIOUS_REPO_NAME = _get_repo_name_from_url_internal(
    DATADOG_MALICIOUS_REPO_URL
)


def make_writable_recursive(path_to_make_writable):
    logging.debug(f"Making {path_to_make_writable} owner-writable.")
    try:
        if os.path.isdir(path_to_make_writable):
            for root, dirs, files in os.walk(path_to_make_writable, topdown=False):
                for name in files:
                    filepath = os.path.join(root, name)
                    try:
                        current_mode = os.stat(filepath).st_mode
                        os.chmod(filepath, current_mode | stat.S_IWUSR)
                    except Exception as e:
                        logging.debug(
                            f"Could not make file {filepath} owner-writable: {e}"
                        )
                for name in dirs:
                    dirpath = os.path.join(root, name)
                    try:
                        current_mode = os.stat(dirpath).st_mode
                        os.chmod(dirpath, current_mode | stat.S_IWUSR | stat.S_IXUSR)
                    except Exception as e:
                        logging.debug(
                            f"Could not make dir {dirpath} owner-writable: {e}"
                        )
            current_mode = os.stat(path_to_make_writable).st_mode
            os.chmod(path_to_make_writable, current_mode | stat.S_IWUSR | stat.S_IXUSR)
        elif os.path.isfile(path_to_make_writable):
            current_mode = os.stat(path_to_make_writable).st_mode
            os.chmod(path_to_make_writable, current_mode | stat.S_IWUSR)
    except Exception as e:
        logging.warning(
            f"Error in make_writable_recursive for {path_to_make_writable}: {e}"
        )


def make_readonly(path):
    logging.debug(f"Setting group/other read-only permissions for {path}")
    perms_file = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    perms_dir = stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
    try:
        if os.path.isdir(path):
            try:
                current_mode = os.stat(path).st_mode
                os.chmod(path, current_mode | stat.S_IWUSR | stat.S_IXUSR)
            except Exception:
                pass
            for root, dirs, files in os.walk(path, topdown=False):
                for f_name in files:
                    try:
                        os.chmod(os.path.join(root, f_name), perms_file)
                    except Exception as e_file:
                        logging.debug(
                            f"Readonly failed for file {os.path.join(root, f_name)}: {e_file}"
                        )
                for d_name in dirs:
                    try:
                        os.chmod(os.path.join(root, d_name), perms_dir)
                    except Exception as e_dir:
                        logging.debug(
                            f"Readonly failed for dir {os.path.join(root, d_name)}: {e_dir}"
                        )
            os.chmod(path, perms_dir)
        elif os.path.isfile(path):
            os.chmod(path, perms_file)
    except Exception as e:
        logging.debug(
            f"Could not set group/other read-only permissions for {path}: {e}"
        )


def get_repo_name_from_url(url):
    return _get_repo_name_from_url_internal(url)


def run_command(command, working_dir=None, repo_name=""):
    logging.debug(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            cwd=working_dir,
            errors="ignore",
        )
        if result.stderr and not any(
            msg in result.stderr
            for msg in ["Cloning into", "Receiving objects", "Resolving deltas"]
        ):
            logging.debug(f"[{repo_name}] Command stderr: {result.stderr.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(
            f"[{repo_name}] Command failed: {' '.join(command)} (rc={e.returncode})"
        )
        if e.stderr:
            logging.error(f"[{repo_name}] Stderr: {e.stderr.strip()}")
        return False
    except Exception as e:
        logging.error(f"[{repo_name}] Error running command {' '.join(command)}: {e}")
        return False


def get_or_clone_repo(repo_url, target_cache_subdir):
    repo_name = get_repo_name_from_url(repo_url)
    repo_path = os.path.join(target_cache_subdir, repo_name)
    os.makedirs(target_cache_subdir, exist_ok=True)

    # Get pinned commit if available
    pinned_commit = get_pinned_commit_for_url(repo_url)

    # Create cache directory name that includes commit hash for pinned repos
    if pinned_commit:
        # Include first 8 chars of commit hash in path for clarity
        commit_short = pinned_commit[:8]
        repo_path = os.path.join(target_cache_subdir, f"{repo_name}_{commit_short}")
        cache_info = f"pinned to {commit_short}"
    else:
        cache_info = "latest (non-reproducible)"

    if os.path.exists(repo_path):
        logging.info(
            f"Using cached repository {repo_name} ({cache_info}) from {repo_path}"
        )
    else:
        if pinned_commit:
            logging.info(
                f"Cloning {repo_name} from {repo_url} (pinned to {commit_short}) into {repo_path}"
            )
            # Clone the full repository to get the specific commit
            if not run_command(
                ["git", "clone", repo_url, repo_path], repo_name=repo_name
            ):
                logging.error(f"Failed to clone {repo_name}.")
                if os.path.exists(repo_path):
                    try:
                        make_writable_recursive(repo_path)
                        shutil.rmtree(repo_path)
                    except Exception as e_rm:
                        logging.warning(
                            f"Could not clean up partial clone {repo_path}: {e_rm}"
                        )
                return None

            # Checkout the specific commit
            if not run_command(
                ["git", "checkout", pinned_commit],
                working_dir=repo_path,
                repo_name=repo_name,
            ):
                logging.error(
                    f"Failed to checkout commit {pinned_commit} for {repo_name}."
                )
                try:
                    make_writable_recursive(repo_path)
                    shutil.rmtree(repo_path)
                except Exception as e_rm:
                    logging.warning(
                        f"Could not clean up failed checkout {repo_path}: {e_rm}"
                    )
                return None
        else:
            logging.info(
                f"Cloning {repo_name} from {repo_url} (latest commit) into {repo_path}"
            )
            if not run_command(
                ["git", "clone", "--depth", "1", repo_url, repo_path],
                repo_name=repo_name,
            ):
                logging.error(f"Failed to clone {repo_name}.")
                if os.path.exists(repo_path):
                    try:
                        make_writable_recursive(repo_path)
                        shutil.rmtree(repo_path)
                    except Exception as e_rm:
                        logging.warning(
                            f"Could not clean up partial clone {repo_path}: {e_rm}"
                        )
                return None

        make_readonly(repo_path)
    return repo_path


def ensure_writable_for_operation(path_to_check):
    try:
        current_mode = os.stat(path_to_check).st_mode
        if not (current_mode & stat.S_IWUSR):
            new_mode = current_mode | stat.S_IWUSR
            if os.path.isdir(path_to_check) and not (current_mode & stat.S_IXUSR):
                new_mode |= stat.S_IXUSR
            os.chmod(path_to_check, new_mode)
        return True
    except Exception as e:
        logging.debug(f"Could not ensure {path_to_check} owner-writable: {e}")
        if not os.access(
            path_to_check, os.W_OK | (os.X_OK if os.path.isdir(path_to_check) else 0)
        ):
            logging.warning(
                f"Path {path_to_check} not writable/executable & could not be made owner-writable."
            )
            return False
        return True


def unpack_archives_recursively(directory_to_scan, repo_name_being_scanned=None):
    extracted_package_roots = []
    for root, _, files in os.walk(directory_to_scan, topdown=True):
        if not ensure_writable_for_operation(root):
            logging.warning(
                f"Cannot make {root} writable, skipping unpacking in this directory."
            )
            continue

        for filename in list(files):
            filepath = os.path.join(root, filename)
            archive_type = None
            extract_path_name = None
            extraction_succeeded = False  # Flag to track successful extraction

            if filename.endswith(".tar.gz"):
                archive_type = "tar.gz"
                extract_path_name = filename[: -len(".tar.gz")]
            elif filename.endswith(".whl"):
                archive_type = "whl"
                extract_path_name = filename[: -len(".whl")]
            elif filename.endswith(".zip"):
                archive_type = "zip"
                extract_path_name = filename[: -len(".zip")]
                if repo_name_being_scanned == DATADOG_MALICIOUS_REPO_NAME:
                    expected_datadog_zip_path_prefix = os.path.join(
                        directory_to_scan, "samples", "pypi"
                    )
                    if not root.startswith(expected_datadog_zip_path_prefix):
                        logging.debug(
                            f"Skipping zip {filepath} in {repo_name_being_scanned} as it's not under {expected_datadog_zip_path_prefix}"
                        )
                        continue
            elif filename.endswith(".gz") and not filename.endswith(".tar.gz"):
                archive_type = "gz"
                extract_path_name = filename[: -len(".gz")]
            else:
                continue

            logging.debug(f"Attempting to unpack {filepath} (type: {archive_type})")

            if not ensure_writable_for_operation(filepath):
                logging.warning(
                    f"Cannot make archive {filepath} writable for potential deletion, skipping."
                )
                continue

            extract_full_path = os.path.join(root, extract_path_name)

            try:
                if not ensure_writable_for_operation(root):
                    logging.warning(
                        f"Parent directory {root} not writable to create {extract_full_path}, skipping."
                    )
                    continue

                if not os.path.exists(extract_full_path):
                    os.makedirs(extract_full_path, exist_ok=True)
                elif not os.path.isdir(extract_full_path):
                    logging.warning(
                        f"Extraction path {extract_full_path} exists but is not a directory, skipping."
                    )
                    continue

                if not ensure_writable_for_operation(extract_full_path):
                    logging.warning(
                        f"Extraction target {extract_full_path} not writable, skipping."
                    )
                    continue

                if archive_type == "tar.gz":
                    with tarfile.open(filepath, "r:gz") as tar:
                        tar.extractall(path=extract_full_path)
                    logging.debug(
                        f"Successfully unpacked .tar.gz {filepath} to {extract_full_path}"
                    )
                    extraction_succeeded = True
                elif archive_type in ["whl", "zip"]:
                    try:
                        with zipfile.ZipFile(filepath, "r") as zip_ref:
                            zip_ref.extractall(extract_full_path)
                        logging.debug(
                            f"Successfully unpacked .{archive_type} {filepath} to {extract_full_path}"
                        )
                        extraction_succeeded = True
                    except RuntimeError as e_runtime_zip:
                        if (
                            "encrypted" in str(e_runtime_zip).lower()
                            or "password required" in str(e_runtime_zip).lower()
                        ) and repo_name_being_scanned == DATADOG_MALICIOUS_REPO_NAME:
                            logging.info(
                                f"Encrypted zip {filepath} in {DATADOG_MALICIOUS_REPO_NAME}. Attempting extraction with password."
                            )
                            try:
                                with zipfile.ZipFile(filepath, "r") as zip_ref_pwd:
                                    zip_ref_pwd.extractall(
                                        extract_full_path, pwd=ENCRYPTED_ZIP_PASSWORD
                                    )
                                logging.info(
                                    f"Successfully unpacked encrypted .{archive_type} {filepath} with password to {extract_full_path}"
                                )
                                extraction_succeeded = True
                            except RuntimeError as e_pwd_failed:
                                logging.warning(
                                    f"Failed to extract encrypted zip {filepath} with password: {e_pwd_failed}"
                                )
                            except Exception as e_pwd_generic_failed:
                                logging.error(
                                    f"Error extracting encrypted zip {filepath} with password: {e_pwd_generic_failed}"
                                )
                        else:
                            logging.warning(
                                f"Skipping zip file {filepath} due to unhandled RuntimeError: {e_runtime_zip}"
                            )
                    except zipfile.BadZipFile as e_zip_bad:
                        logging.debug(
                            f"Skipping file {filepath} as it's not a valid .whl/.zip file or is corrupted: {e_zip_bad}"
                        )
                elif archive_type == "gz":
                    decompressed_file_path = os.path.join(
                        extract_full_path, os.path.basename(extract_path_name)
                    )
                    with gzip.open(filepath, "rb") as f_in:
                        with open(decompressed_file_path, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    logging.debug(
                        f"Successfully decompressed .gz {filepath} to {decompressed_file_path}"
                    )
                    extraction_succeeded = True

                if extraction_succeeded:
                    extracted_package_roots.append(extract_full_path)
                    make_readonly(extract_full_path)
                    try:
                        if ensure_writable_for_operation(
                            filepath
                        ):  # Ensure original archive is writable before deleting
                            os.remove(filepath)
                            logging.debug(f"Successfully removed archive {filepath}")
                        else:
                            logging.warning(
                                f"Could not make {filepath} writable to remove it."
                            )
                    except OSError as e_remove:
                        logging.error(
                            f"Failed to remove archive {filepath} after extraction: {e_remove}"
                        )

            except tarfile.ReadError as e_tar:
                logging.debug(
                    f"Skipping file {filepath} as it's not a valid tar.gz file or is corrupted: {e_tar}"
                )
            except gzip.BadGzipFile as e_gzip:
                logging.debug(
                    f"Skipping file {filepath} as it's not a valid .gz file or is corrupted: {e_gzip}"
                )
            except EOFError as e_eof:
                logging.debug(
                    f"Skipping file {filepath} due to EOFError (possibly corrupted): {e_eof}"
                )
            except Exception as e_unpack:  # General catch-all for other issues in this file's processing
                logging.error(f"Failed to unpack or process {filepath}: {e_unpack}")
    return list(set(extracted_package_roots))


def process_benign_repositories(repo_urls):
    logging.info("Processing benign repositories...")
    processed_paths = []
    for repo_url in repo_urls:
        repo_name = get_repo_name_from_url(repo_url)
        try:
            cloned_repo_path = get_or_clone_repo(repo_url, BENIGN_REPOS_CACHE_PATH)
            if not cloned_repo_path:
                continue

            processed_paths.append(cloned_repo_path)
            logging.info(f"Processing benign: {repo_name}")
            # Placeholder for actual processing logic
        except Exception as e:
            logging.error(f"Error processing benign repo {repo_name}: {e}")
    return processed_paths


def process_rust_repositories(repo_urls):
    logging.info("Processing rust repositories...")
    processed_paths = []
    for repo_url in repo_urls:
        repo_name = get_repo_name_from_url(repo_url)
        try:
            cloned_repo_path = get_or_clone_repo(repo_url, RUST_REPOS_CACHE_PATH)
            if not cloned_repo_path:
                continue

            processed_paths.append(cloned_repo_path)
            logging.info(f"Processing rust: {repo_name}")
            # Placeholder for actual processing logic
        except Exception as e:
            logging.error(f"Error processing rust repo {repo_name}: {e}")
    return processed_paths


def process_malicious_repositories(repo_urls_list):
    logging.info("Processing malicious repositories...")
    all_processed_package_paths = []

    for repo_url in repo_urls_list:
        repo_name = get_repo_name_from_url(repo_url)
        current_repo_processed_package_paths = []
        logging.info(f"Processing malicious repository: {repo_name} from {repo_url}")
        try:
            cloned_mal_repo_path = get_or_clone_repo(
                repo_url, MALICIOUS_REPOS_CACHE_PATH
            )
            if not cloned_mal_repo_path:
                continue

            make_writable_recursive(cloned_mal_repo_path)
            logging.info(f"Unpacking archives in malicious repo: {repo_name}")
            extracted_package_paths = unpack_archives_recursively(
                cloned_mal_repo_path, repo_name_being_scanned=repo_name
            )
            make_readonly(cloned_mal_repo_path)

            if not extracted_package_paths:
                logging.warning(
                    f"No applicable packages extracted from {cloned_mal_repo_path}."
                )
            else:
                logging.info(
                    f"Found {len(extracted_package_paths)} malicious packages/extracted directories in {repo_name} for processing."
                )
                for package_path in extracted_package_paths:
                    descriptive_package_name = f"{repo_name}_{os.path.relpath(package_path, cloned_mal_repo_path).replace(os.sep, '_')}"
                    logging.info(
                        f"Processing malicious package content at: {package_path} (derived from {descriptive_package_name})"
                    )
                    current_repo_processed_package_paths.append(package_path)
            all_processed_package_paths.extend(current_repo_processed_package_paths)
        except Exception as e:
            logging.error(f"Error processing malicious repo {repo_name}: {e}")
    return all_processed_package_paths


def main():
    parser = argparse.ArgumentParser(
        description="Clone/use cached repositories and process them."
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=["benign", "malicious", "rust", "all"],
        default="all",
        help="Type of dataset to process (default: all)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "--use-latest",
        action="store_true",
        help="Use latest commits instead of pinned versions (non-reproducible)",
    )
    parser.add_argument(
        "--force-repin",
        action="store_true",
        help="Force regeneration of pinned repositories configuration",
    )
    args, unknown = parser.parse_known_args()
    if unknown:
        logging.debug(f"Ignoring unknown arguments: {unknown}")

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.INFO)

    # Handle pinning options
    global USE_PINNED_COMMITS
    if args.use_latest:
        USE_PINNED_COMMITS = False
        logging.info("Using latest commits (non-reproducible mode)")
    else:
        USE_PINNED_COMMITS = True
        logging.info("Using pinned commits for reproducible training")

    # Handle force repin option
    if args.force_repin:
        logging.info("Force regenerating pinned repositories configuration...")
        import subprocess

        try:
            result = subprocess.run(
                ["uv", "run", "python", "util/pin_repositories.py"],
                capture_output=True,
                text=True,
                check=True,
            )
            logging.info("Successfully regenerated pinned repositories configuration")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to regenerate pinned repositories: {e}")
            logging.error(f"Stdout: {e.stdout}")
            logging.error(f"Stderr: {e.stderr}")
            return

    logging.info(
        f"Initializing script, using cache directory: {os.path.abspath(REPO_CACHE_DIR)}"
    )
    os.makedirs(BENIGN_REPOS_CACHE_PATH, exist_ok=True)
    os.makedirs(MALICIOUS_REPOS_CACHE_PATH, exist_ok=True)
    os.makedirs(RUST_REPOS_CACHE_PATH, exist_ok=True)

    if args.type in ["benign", "all"]:
        process_benign_repositories(BENIGN_REPO_URLS)

    if args.type in ["malicious", "all"]:
        process_malicious_repositories(MALICIOUS_REPO_URLS)

    if args.type in ["rust", "all"]:
        process_rust_repositories(RUST_REPO_URLS)

    logging.info("Script execution finished.")


if __name__ == "__main__":
    main()
