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
    "https://github.com/pymatting/pymatting/tree/afd2dec073cb08b8119300feec18c179a9d436f3",
    "https://github.com/0rpc/zerorpc-python/tree/668af5b55c01e983cfa6c58b1c1db664460133a9",
    "https://github.com/aaugustin/websockets/tree/1c8032acb16b2de9d3a63a747eb0ee15feffb41d",
    "https://github.com/abhiTronix/vidgear/tree/5f4127b06b9e3e53f9a8d4191609ac41a3b82ad4",
    "https://github.com/aboSamoor/polyglot/tree/9b93b2ecbb9ba1f638c56b92665336e93230646a",
    "https://github.com/ahupp/python-magic/tree/62bd3c6a562b26e4005a012c30a0e86428b8defc",
    "https://github.com/aio-libs/aiohttp/tree/0e9eccb4da65f56739abee18ef0951db5c3fa3c1",
    "https://github.com/aizvorski/scikit-video/tree/f03bf543e5fcde0ed27f31324aa8a502468033cc",
    "https://github.com/ajenti/ajenti/tree/3ed66dde83ce2ec841a2ce3a5e7aff848b1be741",
    "https://github.com/alecthomas/voluptuous/tree/4a9c8f8efba20622afdc68e4721787efb4f17472",
    "https://github.com/Alir3z4/html2text/tree/92c191e6abac90957cffabcec316915032d22d9f",
    "https://github.com/altair-viz/altair/tree/ea3a6e206b31407714e3619458b3cb9d9c4d7e92",
    "https://github.com/amitt001/delegator.py/tree/194aa92543fbdbfbae0bcc24ca217819a7805da2",
    "https://github.com/amoffat/sh/tree/ea434f0bafd285bbe5b93d218e62227f2b77f310",
    "https://github.com/andialbrecht/sqlparse/tree/a801100e9843786a9139bebb97c951603637129c",
    "https://github.com/ansible/ansible/tree/7ac74ab5917de0397a2cd2e10ef37c13fa97d62b",
    "https://github.com/apache/spark/tree/6b86244834fcc589aac60260beb10061b744831a",
    "https://github.com/arrow-py/arrow/tree/1d70d0091980ea489a64fa95a48e99b45f29f0e7",
    "https://github.com/asweigart/pyautogui/tree/b4255d0be42c377154c7d92337d7f8515fc63234",
    "https://github.com/AtsushiSakai/PythonRobotics/tree/cfaab296a4212948333f6316e98575ef904a0932",
    "https://github.com/aws/aws-cli/tree/9dfbae4a41ba55075141868bb85d486c7ba1ca8a",
    "https://github.com/aws/aws-sam-cli/tree/c5a5a5d0f9f5f3694d0b8fcd6118c7f371dd66a8",
    "https://github.com/aws/aws-sdk-pandas/tree/3b941897ddcc8184333c9428a15337876804bf12",
    "https://github.com/aws/deep-learning-containers/tree/60baa0ca56f6853628aab67e304272130903d999",
    "https://github.com/aws/serverless-application-model/tree/79cf1865498ed55a63c98d973d9edd6ac18a4aa4",
    "https://github.com/Azure/Azure-Sentinel/tree/5e6f1a82bd1da8c2b2e8c0cda9bf767f393146bf",
    "https://github.com/bbangert/beaker/tree/913d195875899b31fdbf8b4fda64094870e2d3d6",
    "https://github.com/beetbox/audioread/tree/577f8e2cbe99f33dd7d236deb1626e372f4762e9",
    "https://github.com/beetbox/beets/tree/d487d675b9115672c484eab8a6729b1f0fd24b68",
    "https://github.com/benedekrozemberczki/karateclub/tree/cb46a91df8dcbeb2570debcf6a9d0c518107a2de",
    "https://github.com/benfred/implicit/tree/b33b809cb585cb8a65ad39d0f97497d37e98acaa",
    "https://github.com/benfred/py-spy/tree/1fa3a6ded252d7c1c0ff974a4fcd1af67a1577cf",
    "https://github.com/benhamner/Metrics/tree/9a637aea795dc6f2333f022b0863398de0a1ca77",
    "https://github.com/benoitc/gunicorn/tree/a86ea1e4e6c271d1cd1823c7e14490123f9238fe",
    "https://github.com/bloomberg/bqplot/tree/de6fa802155eb82814219b43614fbce955982bb0",
    "https://github.com/Bogdanp/dramatiq/tree/90c66487f47dfd9cb9a33499de7d99291f822774",
    "https://github.com/bokeh/bokeh/tree/c22a3e7bcdce367d0cd21b92d3737c848036b9ef",
    "https://github.com/boppreh/keyboard/tree/d232de09bda50ecb5211ebcc59b85bc6da6aaa24",
    "https://github.com/boppreh/mouse/tree/7b773393ed58824b1adf055963a2f9e379f52cc3",
    "https://github.com/borgbackup/borg/tree/4d43e136a677a71d5a84e8a82c703993883fcc90",
    "https://github.com/boto/boto3/tree/afa9055243a10d24a1585a8ce9de8b5cf3354f99",
    "https://github.com/boto/boto3/tree/afa9055243a10d24a1585a8ce9de8b5cf3354f99",
    "https://github.com/boto/botocore/tree/ec45ca854b17ef07ab4e551f2a45b203f9982be8",
    "https://github.com/bpython/bpython/tree/44081096607285503c5b384e7653515d0c53ffdc",
    "https://github.com/buildout/buildout/tree/1972dc2f879e67c93a348c47a3187c31e32828ff",
    "https://github.com/buriy/python-readability/tree/c8d8011f3d4c69d7667a52395237e56e66af8ea4",
    "https://github.com/burnash/gspread/tree/f118a0f6104701191802c56cf30eda3c84fd4c1e",
    "https://github.com/canonical/cloud-init/tree/7bd9659c835eb2a17deb3b0d7327603a97a88a2f",
    "https://github.com/carlosescri/DottedDict/tree/27553b5ac9b32d6783c9628feee2f6d25b9024f5",
    "https://github.com/cdgriffith/Box/tree/b071107161228f32762ece8f6039b6906c2570db",
    "https://github.com/chapmanb/bcbb/tree/320353c64ee0dc938113ca36f19b2e6de6b597be",
    "https://github.com/chapmanb/bcbio-nextgen/tree/594339fd1a9694c8f8ed61084e2bd5740cfd59b0",
    "https://github.com/chardet/chardet/tree/8e8dfcd93c572c2cbe37585e01662a90b16fbab6",
    "https://github.com/chriskiehl/Gooey/tree/be4b11b8f27f500e7326711641755ad44576d408",
    "https://github.com/ChrisKnott/Eel/tree/41e2d8a9ac1696def4b4dd2c440fa85538a6d6df",
    "https://github.com/ChristosChristofidis/awesome-deep-learning/tree/f9c4c7b6c42f8d325f8ac880508cf7003ef60a0a",
    "https://github.com/CleanCut/green/tree/e89b49146c8767ff4a0cedf05f6e8dffcba8e0cd",
    "https://github.com/clips/pattern/tree/d25511f9ca7ed9356b801d8663b8b5168464e68f",
    "https://github.com/cobrateam/splinter/tree/1ff107b9776deabfee6febb357b541c0019f961a",
    "https://github.com/codeinthehole/purl/tree/2bd51cabecfd4dcd20544fba7092cfd98dc7dac0",
    "https://github.com/codelucas/newspaper/tree/ba8d2f41be9618a6f1112355082c892d3c3e1177",
    "https://github.com/coleifer/huey/tree/302fb8ed8c4894ee7b419f91a22ec53b236fe50c",
    "https://github.com/coleifer/micawber/tree/1e8b8af3cc3c3f2a7d597a100b4de71533d24ceb",
    "https://github.com/coleifer/peewee/tree/66fe9b8290c9e93d1c875ed44831bd932ac26e0c",
    "https://github.com/conda/conda//tree/8ea36ec4ee0beeab2c1027517a987c74098ef2f9",
    "https://github.com/cookiecutter/cookiecutter/tree/b4451231809fb9e4fc2a1e95d433cb030e4b9e06",
    "https://github.com/copier-org/copier/tree/608b5d474be28a7cbaa6518fdebdcb1ee6c1e9cd",
    "https://github.com/Cornices/cornice/tree/1d398c78299b9f66da55e2233d873a9481d92478",
    "https://github.com/crossbario/autobahn-python/tree/edc3c94c3cff717c9128217115dc6b980e2784ea",
    "https://github.com/cython/cython/tree/b2dd10740a087310cd5a72d6f0c611b556396a5e",
    "https://github.com/dabeaz/ply/tree/5c4dc94d4c6d059ec127ee1493c735963a5d2645",
    "https://github.com/dahlia/awesome-sqlalchemy/tree/6e5f45aa6526afc980b548f8c7f1a12ce8e103ec",
    "https://github.com/dashingsoft/pyarmor/tree/f337fefca0e03299d70058a9497dba58592a741f",
    "https://github.com/dask/dask/tree/abdb435dde0be15b262e9ad4657238c2bcb320c9",
    "https://github.com/datafolklabs/cement/tree/9df6b3a3d3d1e044bc38377337d3380d013668b8",
    "https://github.com/datastax/python-driver/tree/c5bed09bf03cd1ceb7780572043713f946da8cd8",
    "https://github.com/dateutil/dateutil/tree/35ed87a02ad777428a9da84ead4d8425b533d4a9",
    "https://github.com/davidaurelio/hashids-python/tree/09f879a1967836f1e399c12b745c24291e3e73ad",
    "https://github.com/daviddrysdale/python-phonenumbers/tree/e90d8ea1167ee6afa173822ce4fef0d7ac31be17",
    "https://github.com/davidhalter/jedi-vim/tree/344814c214391368674813e3a11143448e73e749",
    "https://github.com/davidhalter/jedi/tree/c4f0538930a9a65bc3b1e18d20600624ce907460",
    "https://github.com/dbader/schedule/tree/82a43db1b938d8fdf60103bd41f329e06c8d3651",
    "https://github.com/dbcli/litecli/tree/c726e9e3b0ef704a13dd6758599a48d552f72431",
    "https://github.com/dbcli/mycli/tree/3ef37c47fe3748fd26941670114d865a50a3f5f6",
    "https://github.com/dbcli/pgcli/tree/435cf7f2843c1a161ad63d72b75b91d1ccba8200",
    "https://github.com/deanmalmgren/textract/tree/ec3c0c3c982078d22e51cc2753baeaf48cdf2e19",
    "https://github.com/Delgan/loguru/tree/a69bfc451413f71b81761a238db4b5833cf0a992",
    "https://github.com/derek73/python-nameparser/tree/759a1316f2fda4395714f36d777fd014dcdd51b0",
    "https://github.com/devpi/devpi/tree/7b318e205b5470b7d13db1432b2b14506b1423fe",
    "https://github.com/devsnd/tinytag/tree/f396b74d001b364f49bf51295ff9f078cdbd0262",
    "https://github.com/dfunckt/django-rules/tree/6ce69d03bab6831ecfa194765b42110439ebe1bb",
    "https://github.com/dhamaniasad/awesome-postgres/tree/93742cf11a43cf09aea7d2afba308e904ed048e6",
    "https://github.com/DiffSK/configobj/tree/de98b6ec2ee43b311186cc5b14b91a0982e14f2f",
    "https://github.com/dimka665/awesome-slugify/tree/a6563949965bcddd976b7b3fb0babf76e3b490f7",
    "https://github.com/django-cache-machine/django-cache-machine/tree/01f12b9a4907064440dcd8b2d4b1375b26b11e4d",
    "https://github.com/django-compressor/django-compressor/tree/3a82c435b84b5d30e7899a771b3ad77defb77b6c",
    "https://github.com/django-guardian/django-guardian/tree/c1452be88506514f18ec58fe7db45b75707b7993",
    "https://github.com/django-haystack/django-haystack/tree/a6516b2e9ec6f00600a4745283a3873cebbc40ff",
    "https://github.com/django-haystack/pysolr/tree/249b5e987c25557d4c09b362a147b8e66ecdec45",
    "https://github.com/django-tastypie/django-tastypie/tree/03c4746f0a0f88628be5264bc8d4a19a0529b2f4",
    "https://github.com/django/channels/tree/94702b6d1de8c19969d721410662a9184e74dbd1",
    "https://github.com/django/daphne/tree/b8b4d2a5f7f37e1fd2e8cfd2b5144eb9f4beb641",
    "https://github.com/django/django/tree/42ab99309d347f617d60751c2e8d627fb2963049",
    "https://github.com/django/django/tree/42ab99309d347f617d60751c2e8d627fb2963049",
    "https://github.com/DLR-RM/BlenderProc/tree/1dfe3b1c799233b57feb5753ad9cfb1cd3ac86a5",
    "https://github.com/DLR-RM/stable-baselines3/tree/f9c4ca57ef726eb20e2be959b7035c7cfa0c9e59",
    "https://github.com/dmlc/xgboost/tree/9ad4e2445bb2fa873f63d141b90d453ef61b7e32",
    "https://github.com/DmytroLitvinov/awesome-flake8-extensions/tree/4630efed49f6e0ff2e4f8513da53145c8665c594",
    "https://github.com/dpkp/kafka-python/tree/00a5e6c6c304bdb95d059a6abd448db712bbf8ad",
    "https://github.com/dry-python/returns/tree/ff43e2a99b5b2c9ed969287ca4aeb7d182bf72ec",
    "https://github.com/dylanaraps/pywal/tree/236aa48e741ff8d65c4c3826db2813bf2ee6f352",
    "https://github.com/elapouya/python-docx-template/tree/399761f9c9c1fed8b1f1f30b37b5a1bf0063cb6a",
    "https://github.com/elastic/elasticsearch-dsl-py/tree/05fae5ea1b8edb05c42aae2b4160e42467b21432",
    "https://github.com/eliben/pycparser/tree/f04fdcde3d95be4a632948718d0c46eac09c50ce",
    "https://github.com/eliben/pyelftools/tree/400d51b863f3f7c57a5659f9e44fb86863b76cd0",
    "https://github.com/ellisonleao/pyshorteners/tree/940bde19fb594cd8b7d102c6750bb6344997aa52",
    "https://github.com/emcconville/wand/tree/20dbf7954b9b80bca938422bea8aac22620ed25a",
    "https://github.com/emirozer/fake2db/tree/5a7c0d55a47c903e8c1fead016fb0d2d01e88b3d",
    "https://github.com/encode/django-rest-framework/tree/c0202a0aa5cbaf8573458b932878dfd5044c93ab",
    "https://github.com/encode/httpx/tree/6c7af967734bafd011164f2a1653abc87905a62b",
    "https://github.com/encode/orm/tree/062f7e03d62d7b30bd1d7ae68152c7b0a6b3535e",
    "https://github.com/encode/uvicorn/tree/fa3d9d27dbe7ecbc68e0992309d0ba49ead5640b",
    "https://github.com/erikrose/more-itertools/tree/67180f89ad1147a530aa8f7a829e64a81624e774",
    "https://github.com/errbotio/errbot//tree/3c3af1a00fc9ec047133f2a248eccec0e4a6d551",
    "https://github.com/esnme/ultrajson/tree/2ea54f6a1d1b8e2bc3a27c491a63238cf244f087",
    "https://github.com/eventlet/eventlet/tree/a4d7fe4dae5c5c14f581aedfb5a704c1714e9101",
    "https://github.com/evhub/coconut/tree/4659175b85040d591f344b1648b6dd33e7b84962",
    "https://github.com/fabric/fabric/tree/988dd0fd05db47331cb43d0ea9787908ef33219c",
    "https://github.com/facebook/PathPicker/tree/c1dd1f7fc4dae5aa807218cf086942f1c9241783",
    "https://github.com/facebook/pyre-check/tree/0bc781a2ac052b8992e3924d1905c8e78bf84f4f",
    "https://github.com/facebookresearch/detectron2/tree/536dc9d527074e3b15df5f6677ffe1f4e104a4ab",
    "https://github.com/facebookresearch/fairseq/tree/ecbf110e1eb43861214b05fa001eff584954f65a",
    "https://github.com/facebookresearch/hydra/tree/0f83b0dd6127bf7acb9b31d93e62a7c10b640011",
    "https://github.com/facebookresearch/pytext/tree/08754b483421884d2e363f00517ea42e449aec2c",
    "https://github.com/FactoryBoy/factory_boy/tree/68feb45e182f9acccfde671b7ba0babb5bc7ce11",
    "https://github.com/faif/python-patterns/tree/879ac0107f7f0005767d0e67c1555f54515c10ae",
    "https://github.com/falconry/falcon/tree/0c3b322668eebe92be7532b7b71d7847e1dd3cf7",
    "https://github.com/fastapi/fastapi/tree/f3bfa3b8a510a6e7aa7f212dfddee50f7a948883",
    "https://github.com/feincms/feincms/tree/aaae1ef7368f8b306d9e8a6fa594e867a5637017",
    "https://github.com/fengsp/plan/tree/1f7b212e041599c4399dd2077c9d65b35ea5e260",
    "https://github.com/fighting41love/funNLP/tree/29f4ac896f11058e87e10968569f999c69679b6f",
    "https://github.com/flask-admin/flask-admin/tree/87f7c0bbf40cd1d506ea201b047cc45488eb740a",
    "https://github.com/flask-api/flask-api/tree/5c92f76278315e2d1cfbf55d4acaa66102c6c622",
    "https://github.com/flask-restful/flask-restful/tree/88cce53a8cd65830bf1815185a42ba24e5db78c6",
    "https://github.com/fogleman/Quads/tree/8f0376f78fa6bea4e9bd03e2cd5fe4e4ae72cfe1",
    "https://github.com/fxsjy/jieba/tree/67fa2e36e72f69d9134b8a1037b83fbb070b9775",
    "https://github.com/gabrielfalcao/HTTPretty/tree/f9f012711597634d40066d144a36888b3addcc46",
    "https://github.com/gaojiuli/toapi/tree/6ae043cab28d16beb0be1bd9b1cd0fdc9c19baa6",
    "https://github.com/gawel/pyquery/tree/811cd048ffbe4e69fdc512863671131f98d691fb",
    "https://github.com/geopy/geopy/tree/f495974c32a7a7b1eb433e7b8c87166e96375c32",
    "https://github.com/getnikola/nikola/tree/0f4c230e5159e4e937463eb8d6d2ddfcbb09def2",
    "https://github.com/getpelican/pelican/tree/487486138ffd2f27327b990d8dcc3088da4064e9",
    "https://github.com/getsentry/responses/tree/9ea86fe6af7626e7b270e128b1e8c521c013d948",
    "https://github.com/getsentry/sentry-python/tree/eee4cac8f8ae44e5bee9364a482597680b81b52f",
    "https://github.com/gevent/gevent/tree/73025a8837b3bff19c106e877fa2374889c59dd3",
    "https://github.com/giampaolo/psutil/tree/9b199cce618fe2da6e6419e53e23714f8edcc94e",
    "https://github.com/glamp/bashplotlib/tree/db4065cfe65c0bf7c530e0e8b9328daf9593ad74",
    "https://github.com/gleitz/howdoi/tree/033dd3ced06761d9d0b3a52068ea358405ab79d9",
    "https://github.com/google/google-api-python-client/tree/614d1ef48b0f3fc38bb60b444228a291923e68c9",
    "https://github.com/google/python-fire/tree/8527235d18835223dad5055e29d50664ab5bfb2d",
    "https://github.com/google/python-fire/tree/8527235d18835223dad5055e29d50664ab5bfb2d",
    "https://github.com/google/pytype/tree/7a0e7b9e70fe91c191ac58dc5311e8a380a54322",
    "https://github.com/google/yapf/tree/12005095296072751e3e4c1f33a047d41b0ce18d",
    "https://github.com/googleapis/google-api-python-client/tree/614d1ef48b0f3fc38bb60b444228a291923e68c9",
    "https://github.com/gorakhargosh/watchdog/tree/1c4d80e09cf6a0e9c6fd1ead6d0f6bdaebcd374c",
    "https://github.com/gotcha/ipdb/tree/400e37c56c9772fdc4c04ddb29d8a4a20568fb1a",
    "https://github.com/grantjenks/python-diskcache/tree/ebfa37cd99d7ef716ec452ad8af4b4276a8e2233",
    "https://github.com/grantjenks/python-sortedcontainers/tree/3ac358631f58c1347f1d6d2d92784117db0f38ed",
    "https://github.com/graphql-python/graphene//tree/82903263080b3b7f22c2ad84319584d7a3b1a1f6",
    "https://github.com/gruns/furl/tree/7c233324610338414f77a37a2f1e1dc75b4bc9b0",
    "https://github.com/gruns/icecream/tree/851f0fd1fe5073488531bbb29942bd1c181cfd12",
    "https://github.com/guestwalk/libffm/tree/af3ae37c09e31b95ebbc944d21494029122e58e5",
    "https://github.com/gunnery/gunnery/tree/733a261cae6243a11883a40e18b14f57cf6e47b2",
    "https://github.com/h2oai/h2o-3/tree/e6a314be0804d41a70deff25ab4e924e7e1b6669",
    "https://github.com/has2k1/plotnine/tree/9bb7cb5854406d5f0efaa2185e5b3897b5084f56",
    "https://github.com/HBNetwork/python-decouple/tree/0573e6f96637f08fb4cb85e0552f0622d36827d4",
    "https://github.com/hi-primus/optimus/tree/cb73842d5662f9781bacb50afd24b94cfb586b95",
    "https://github.com/html5lib/html5lib-python/tree/fd4f032bc090d44fb11a84b352dad7cbee0a4745",
    "https://github.com/httpie/cli/tree/5b604c37c6c67e18e7c3e9aee6c88a8c22b98345",
    "https://github.com/hugapi/hug/tree/e4a3fa40f98487a67351311d0da659a6c9ce88a6",
    "https://github.com/huggingface/transformers/tree/716819b8309324302e00a3488a3c3d6faa427f79",
    "https://github.com/humiaozuzu/awesome-flask/tree/df6f650f176433d3296482a51b38356fb3626abb",
    "https://github.com/HypothesisWorks/hypothesis/tree/0a54469102d04f8fbc849bbcb8853c619cca3e90",
    "https://github.com/ibayer/fastFM/tree/9f30c5564a8d365105876f4e5d751c46e57dc983",
    "https://github.com/indico/indico/tree/5090fde216eaabc7fa64e2a45d8967eb3c43bd2f",
    "https://github.com/inducer/pudb/tree/b6e2f9da29b3d330c3f56913e74884231a95b0ed",
    "https://github.com/Instagram/MonkeyType/tree/70c3acf62950be5dfb28743c7a719bfdecebcd84",
    "https://github.com/ionelmc/python-hunter/tree/5689bae52b2a8e32e7a4e509534486f136330a24",
    "https://github.com/ionelmc/python-manhole/tree/175f426fc4794ae9a54f9daba032e3e5631e7db3",
    "https://github.com/IronLanguages/ironpython3/tree/00fdda440ba4a4a3cc64da13c72494832054b547",
    "https://github.com/isnowfy/snownlp/tree/fad6ae77d6c545e09fa91b8ac90bab8864c84177",
    "https://github.com/istrategylabs/django-wordpress/tree/285c10c4afa564e5211b5d82558baeb961de82e8",
    "https://github.com/jab/bidict/tree/03ece106f8eb0f77baf983abc88b7ce4735edd4e",
    "https://github.com/JaidedAI/EasyOCR/tree/c4f3cd7225efd4f85451bd8b4a7646ae9a092420",
    "https://github.com/jaraco/path.py/tree/2b4025f970a462a82cec58ff8f9adb287a90d419",
    "https://github.com/jazzband/django-debug-toolbar/tree/cf71ded725ddda6124e55762cc2115567d6eec4c",
    "https://github.com/jazzband/django-oauth-toolkit/tree/877e62542e44c1d0a2ddad8a09bb7a8d7b41c44c",
    "https://github.com/jazzband/django-pipeline/tree/f36dbe089d067a20d8e78152e8f5dc83ad2d07ce",
    "https://github.com/jazzband/django-taggit/tree/7af1e7415225ef00c801a7e687137a2a0eb9f323",
    "https://github.com/jazzband/geojson/tree/68901cb26528faeb263e539e6e9bf48bb2525fc2",
    "https://github.com/jazzband/localshop/tree/875ae6d056282bb9d33c07ab69d7bae8e02d5d66",
    "https://github.com/jazzband/pip-tools/tree/e4ed0c1e028d1ca73673a51722ba153f0c02b0c6",
    "https://github.com/jazzband/tablib/tree/6f405f6cfa50e91c0ea6be9058711fe0b35428ed",
    "https://github.com/jeffknupp/sandman2/tree/715500f0d6806ad055766ecba0bd0e022f13a6f7",
    "https://github.com/jek/blinker/tree/c757984aaf08f229bab8aa63df7bb4b48b0be943",
    "https://github.com/jendrikseipp/vulture/tree/1e210d9205f522ea7fc2abee638047d2d97bd2a5",
    "https://github.com/jet-admin/jet-bridge/tree/f0118673dd53922f6b81a8672e42e47c1b787f9a",
    "https://github.com/jfkirk/tensorrec/tree/80690737ac039a5b41fc99e67372c4f67d8cfc51",
    "https://github.com/jiaaro/pydub/tree/996cec42e9621701edb83354232b2c0ca0121560",
    "https://github.com/jindaxiang/akshare/tree/796d2fe9333463c072522ef948c156654a360ccd",
    "https://github.com/jmcnamara/XlsxWriter/tree/a5755af23b43df3b5891094c1ce6d711a9a0a006",
    "https://github.com/JohnLangford/vowpal_wabbit//tree/c0f724bea23d68b5c5e48c2f3899c66a5fc57680",
    "https://github.com/joke2k/faker/tree/cfca7ca223cdeac1afeb4c0ed739f6bc7e608e92",
    "https://github.com/jonathanslenders/ptpython/tree/836431ff6775aac2c2e3aafa3295b259ebe99d0a",
    "https://github.com/jonathanslenders/python-prompt-toolkit/tree/d997aab538e434a6ca07d6bee226fd5b0628262f",
    "https://github.com/jorgenschaefer/elpy/tree/0b381f55969438ab2ccc2d1a1614045fcf7c9545",
    "https://github.com/josephreisinger/vowpal_porpoise/tree/07dfa54c01c9476a47e2464ee66a8553e9944e17",
    "https://github.com/jpadilla/pyjwt/tree/2422bc92a24240f745069bff4320137b7955d785",
    "https://github.com/jschneier/django-storages/tree/9de3cc9da4dbd67fcc56ecafc7cbf738af90136c",
    "https://github.com/justquick/django-activity-stream/tree/27a62e6e671a4762913541121ad72903e0b61cd7",
    "https://github.com/keleshev/schema/tree/3e06d37994442ef3ae5b9a1f8564d5ad598c9a68",
    "https://github.com/keon/algorithms/tree/cad4754bc71742c2d6fcbd3b92ae74834d359844",
    "https://github.com/keras-team/keras/tree/dfaca0e1e8ffc14d68c81e07840049e9953db4ac",
    "https://github.com/keunwoochoi/kapre/tree/af4eb541d733cfed3ec57b10579307e9f5613359",
    "https://github.com/kevin1024/vcrpy/tree/19bd4e012c8fd6970fd7f2af3cc60aed1e5f1ab5",
    "https://github.com/kiddouk/redisco/tree/4f6a3aab761dfe3cfcdffee37426b2659563afde",
    "https://github.com/kiwicom/schemathesis/tree/563bb0ddbe0ae24927826292843f8dcfe01a9c1b",
    "https://github.com/klen/mixer/tree/431ca2756af5571efc4d08d743fa8ab2a8619183",
    "https://github.com/knipknap/SpiffWorkflow/tree/c1e89e3f3b4e2ffd80f7b773ffa302572fc69404",
    "https://github.com/kootenpv/yagmail/tree/0591606f3eb87502a6a16c42c775f66380dd72c1",
    "https://github.com/kornia/kornia//tree/fc0ac03d1a3f523785d3b4166b4358f6bec7ac73",
    "https://github.com/Kozea/pygal/tree/b7c8f2a49e029f4fca043244d3b7d5ca4bec4c47",
    "https://github.com/kurtmckee/feedparser/tree/a39f3d71347a880d5b059c05d5d72c7a516de767",
    "https://github.com/laixintao/iredis/tree/27be126e4ea798115547111752f83c8998d66707",
    "https://github.com/lancopku/pkuseg-python/tree/071d57c7df9ac0680edda7034b47787d7c6f9184",
    "https://github.com/lektor/lektor/tree/1d4357dd615d839ba51b25150600103228e8b108",
    "https://github.com/lemire/simdjson/tree/b717136fd9151422acf78995cb27ec6d43bed7cf",
    "https://github.com/lepture/authlib/tree/7e33d7686dd82aee73e45dfac5822fcefe04a21f",
    "https://github.com/lepture/mistune/tree/ea3ecaf4a5a6667de47f061b1b9a692d2952ad93",
    "https://github.com/lericson/pylibmc/tree/b6e8452bc92232ce434d9d064a73606a94457f5e",
    "https://github.com/libAudioFlux/audioFlux/tree/824f76d5f19d0358779e513d708a987e4fb9224e",
    "https://github.com/librosa/librosa/tree/af8c839fb15317fa2712ea66e7a22da6a9267b32",
    "https://github.com/libvips/pyvips/tree/1208ca690e863a68d4826d3b6868e6ca7b9216ec",
    "https://github.com/Lightning-AI/pytorch-lightning/tree/01ba7a1489498858617690ab921e84d5479c2eb1",
    "https://github.com/lincolnloop/python-qrcode/tree/3704f57a1107dbf553a50f5b531da3859abe19cf",
    "https://github.com/linkedin/shiv/tree/a353d10ecd785c6bd67ccd08b642437e7204be57",
    "https://github.com/lk-geimfari/mimesis/tree/b981966db9b42474fd26470e35098b640d5451e9",
    "https://github.com/locustio/locust/tree/f5584760c2ac6764e4ec2ce5272d655336891692",
    "https://github.com/lorien/grab/tree/35e44c2405b7c944a47df67ba3f024113acce74f",
    "https://github.com/LuminosoInsight/python-ftfy/tree/74dd0452b48286a3770013b3a02755313bd5575e",
    "https://github.com/lyst/lightfm/tree/0c9c31e027b976beab2385e268b58010fff46096",
    "https://github.com/maciejkula/spotlight/tree/75f4c8c55090771b52b88ef1a00f75bb39f9f2a9",
    "https://github.com/madmaze/pytesseract/tree/df9fce0b5c5ea3cd9182fce8870ab9241d951173",
    "https://github.com/magenta/magenta/tree/3972a3d1a9ddeb2e4717855b86d05a43c13fa830",
    "https://github.com/MagicStack/uvloop/tree/96b7ed31afaf02800d779a395591da6a2c8c50e1",
    "https://github.com/mahmoud/boltons/tree/0c88f25323de3ff85bcca844b9ce6cd171a80392",
    "https://github.com/mailgun/flanker/tree/0c774c069509f7f198f4adc1761cb8aa2639902d",
    "https://github.com/Manisso/fsociety/tree/b76ac01449c0bfadb1483890e6def9ec9976815d",
    "https://github.com/Maratyszcza/PeachPy/tree/349e8f836142b2ed0efeb6bb99b1b715d87202e9",
    "https://github.com/markusschanta/awesome-jupyter/tree/270033f62042d5c6de71c298302dde651301e303",
    "https://github.com/marrow/mailer/tree/396509e8ad7d70b07ce5d30946294d09fec020a6",
    "https://github.com/marshmallow-code/marshmallow/tree/7266de0c42e26c521801b7c01417d1f738e8a314",
    "https://github.com/marshmallow-code/webargs/tree/a59bfca9c9c88e0cbaa97eb2cdba3683e8cc33a1",
    "https://github.com/martinblech/xmltodict/tree/0952f382c2340bc8b86a5503ba765a35a49cf7c4",
    "https://github.com/martinrusev/imbox/tree/7ec744ba4698c2aaa43c599e6463a9ece25f45e7",
    "https://github.com/MasoniteFramework/masonite/tree/28cf12194a436eb669128b6c30b232065a5052c5",
    "https://github.com/matplotlib/matplotlib/tree/f0a1206fa957d0caa58cef0065a3992a161df66d",
    "https://github.com/MechanicalSoup/MechanicalSoup/tree/9185169ab94bc9444d6ed3d768599a1620aacf45",
    "https://github.com/metawilm/cl-python/tree/66eb75edd0506fc1a22819a4f15546c35ac429c7",
    "https://github.com/mhammond/pywin32/tree/420e4a50e82f211723f9130aa97c5df66d8aec9a",
    "https://github.com/mher/flower/tree/d6898881a36945ebab86d6f00f1d2d16dbac7b06",
    "https://github.com/michaelhelmick/lassie/tree/1122c719a68c20b847c1963719070e10a3d253dd",
    "https://github.com/micropython/micropython/tree/44bcfe53de6fdc1f3eb0f104798f5679d7b4473d",
    "https://github.com/microsoft/markitdown/tree/041be5447148e7455d38af986b1fc64bc420b62a",
    "https://github.com/Microsoft/PTVS/tree/e98529df810b718e51f7f033dac43347ca35627c",
    "https://github.com/mindflayer/python-mocket/tree/663d053073ae426ece20d5397decaea0b067dd65",
    "https://github.com/mindsdb/mindsdb/tree/95687d31ac8b25217a4ac9905b50c959fabaceb2",
    "https://github.com/mingrammer/diagrams/tree/134d5cd72da35027393081a1bbc740199c388a92",
    "https://github.com/mininet/mininet/tree/6eb8973c0bfd13c25c244a3871130c5e36b5fbd7",
    "https://github.com/miracle2k/flask-assets/tree/62efd23fe95ee6a86fc1cfaa98fc1e2152093557",
    "https://github.com/miracle2k/webassets/tree/17d540ef9e0d7ca53aab06322d0e16fd92b59539",
    "https://github.com/miso-belica/sumy/tree/d31ead33831275c0e8d595f69174d9f129f8944a",
    "https://github.com/mitmproxy/pdoc/tree/2ab4df12693678439a9063f0e3909c26545241a9",
    "https://github.com/mitsuhiko/pluginbase/tree/2a5db4c0bba11dc6dff0110c298e3ab9d8521532",
    "https://github.com/mitsuhiko/unp/tree/199df7b1e126573f400dfa8adb4b6961078df6bf",
    "https://github.com/mkdocs/mkdocs//tree/4c7404485f988f409ccaf42fefe705222ff5965a",
    "https://github.com/mlflow/mlflow/tree/72b7a44ebfbf7ee1c0bd14de97315bdddf0b15ef",
    "https://github.com/mobolic/facebook-sdk/tree/3fa89fec6a20dd070ccf57968c6f89256f237f54",
    "https://github.com/modoboa/modoboa/tree/93b99f17373833504c732ac2dbfe78e9b345c9e2",
    "https://github.com/moggers87/salmon/tree/a9f1355cd26e14a2c55a12156016c066f757fea4",
    "https://github.com/mongodb/mongo-python-driver/tree/a435a3e1c385dce4129bf8e1f86d98266569626a",
    "https://github.com/mongodb/motor/tree/71c3cf9dda7c5deea6fbf452a9495dfc5fe403db",
    "https://github.com/MongoEngine/mongoengine/tree/e51ee40e7dad8e147992ae762e99a0c189a69028",
    "https://github.com/moses-palmer/pynput/tree/74c5220a61fecf9eec0734abdbca23389001ea6b",
    "https://github.com/mozilla/bleach/tree/9a68c6789a7b31d2a9bc86f1ee2924d5de6ecc5c",
    "https://github.com/mozilla/unicode-slugify/tree/74d175dd4c9d21b1586842a3909118c7ec58f4ce",
    "https://github.com/mozillazg/python-pinyin/tree/789d258834832e1e6029efdb6d7c27ebfe12c22c",
    "https://github.com/mpdavis/python-jose//tree/675f4df8bcef431019e515f8728cf4fb2439be7a",
    "https://github.com/mre/awesome-static-analysis/tree/c0fc389cc164a934322425efa157b71f5f1cba8d",
    "https://github.com/msiemens/tinydb/tree/10644a0e07ad180c5b756aba272ee6b0dbd12df8",
    "https://github.com/mstamy2/PyPDF2/tree/11b8195b3649e01c65c85c15b2c722d3afa53168",
    "https://github.com/mwaskom/seaborn/tree/86b5481ca47cb46d3b3e079a5ed9b9fb46e315ef",
    "https://github.com/mymarilyn/clickhouse-driver/tree/8a4e7c5b99b532df2b015651d893a6f36288a22c",
    "https://github.com/napalm-automation/napalm/tree/77921f691a7dd099b1d44ba544d8d12db8f51b06",
    "https://github.com/nficano/python-lambda/tree/2f9f17a5c5993e65ee2b61d06f29ed5a6689d337",
    "https://github.com/nicfit/eyeD3/tree/e8c2aac947387250ff76b22ccbb118b5235c1afa",
    "https://github.com/NicolasHug/Surprise/tree/2381fb11d0c4bf917cc4b9126f205d0013649966",
    "https://github.com/nose-devs/nose2/tree/180cc2eb6f54331d31ee05dfc85233bf60ca2de6",
    "https://github.com/noxrepo/pox/tree/5f82461e01f8822bd7336603b361bff4ffbd2380",
    "https://github.com/nucleic/enaml/tree/aa500d9c7cefb5d6c6e158fe227c5e08bf47888c",
    "https://github.com/numba/numba/tree/b47d53abc5976b022e84beba6545ac344fe51bf1",
    "https://github.com/numenta/nupic/tree/7281482def2a96fbda663e6c39e8351a1886dec7",
    "https://github.com/numpy/numpy/tree/e9e981e9d45335fd6b758e620812772e19143f35",
    "https://github.com/nvbn/thefuck/tree/c7e7e1d884d3bb241ea6448f72a989434c2a35ec",
    "https://github.com/nvdv/vprof/tree/99bb5cd5691a5bfbca23c14ad3b70a7bca6e7ac7",
    "https://github.com/oauthlib/oauthlib/tree/dab6a5ae1830ddd8a79c1e9687f63508eae60b57",
    "https://github.com/openai/gym/tree/dcd185843a62953e27c2d54dc8c2d647d604b635",
    "https://github.com/openembedded/bitbake/tree/2a8722ddd155596862029f6ea34e1e92c77e0b7f",
    "https://github.com/openstack/cliff/tree/af17b570351c6d1d9ce2a2a8879ba0d93d07ca7d",
    "https://github.com/orsinium/textdistance/tree/d6a68d61088a40eef5c88191ccf79323dbf34850",
    "https://github.com/ovalhub/pyicu/tree/1d9be21ed24c04d571b443088222370e2d7e1fe7",
    "https://github.com/pallets-eco/flask-debugtoolbar/tree/40f8645ec9dd1580a2cc52b1731d3f34a8132afd",
    "https://github.com/pallets/click//tree/af73ce4793bf38edf11a16e959ef0d8a0dbf6c1f",
    "https://github.com/pallets/flask/tree/b78b5a210bde49e7e04b62a2a4f453ca10e0048c",
    "https://github.com/pallets/flask/tree/b78b5a210bde49e7e04b62a2a4f453ca10e0048c",
    "https://github.com/pallets/itsdangerous/tree/62fde54d4ff717fa1c4af688dbebf97845fed495",
    "https://github.com/pallets/jinja/tree/220e67ae999c24e4077d7bf5bdc932757b65a338",
    "https://github.com/pallets/markupsafe/tree/620c06c919c1bd7bb1ce3dbee402e1c0c56e7ac3",
    "https://github.com/pallets/werkzeug/tree/7868bef5d978093a8baa0784464ebe5d775ae92a",
    "https://github.com/pandas-dev/pandas/tree/9c5b9ee823702d937d008d761dbe9ae8872f2259",
    "https://github.com/paramiko/paramiko/tree/ed8b09751ff20340332d4b1bb2b10e32aedc57ff",
    "https://github.com/Parisson/TimeSide/tree/7b3929f89dcd897542895aee7df1a9f1cf40de67",
    "https://github.com/Parsely/streamparse/tree/28f45a6e2d2f839f9e6d421c46689d919feda00c",
    "https://github.com/patrys/httmock/tree/98269075d0c36a0e87e2b6b7ad9c6a16622aba58",
    "https://github.com/patx/pickledb/tree/46ab99ffad71ea4fd8c29adcb3aea076e24a1865",
    "https://github.com/pdfminer/pdfminer.six/tree/51683b2528e2aa685dd8b9e61f6ccf9f76a59a62",
    "https://github.com/pennersr/django-allauth/tree/1e72c343752ac244fce92a1829c85bfce90d1309",
    "https://github.com/peterbrittain/asciimatics/tree/6673ea8048b336a40422f037a9515f445df9621c",
    "https://github.com/PetrochukM/PyTorch-NLP/tree/53d7edcb8e0c099efce7c2ddf8cd7c44157fcac3",
    "https://github.com/pgjones/hypercorn/tree/6cb9c5cc11c5372d59ffb8348345e308bc2f1067",
    "https://github.com/planetopendata/awesome-sqlite/tree/41fe46cad6afb60fd6fa3991f00740c7db4eda89",
    "https://github.com/platformio/platformio-core/tree/444c57b4a6f4b1432d0c660cdcd6f9c9cd9b014f",
    "https://github.com/ponyorm/pony//tree/b9375605edacde9e68e3fc5c578a4b090a36cb8d",
    "https://github.com/prabhupant/python-ds/tree/35d3556a992ceccc5b925afa892fae3ba01a0e81",
    "https://github.com/PrefectHQ/prefect/tree/95a0ccedd4626c1a737d41a2d4aac25072d606cd",
    "https://github.com/pricingassistant/mrq/tree/5a1154dc6a60d8b6d6423937f6569ce8fb0347b6",
    "https://github.com/prompt-toolkit/python-prompt-toolkit/tree/d997aab538e434a6ca07d6bee226fd5b0628262f",
    "https://github.com/psf/black/tree/314f8cf92b285de3d95bb6b86c66cc7ce252b6c1",
    "https://github.com/psf/requests-html/tree/075ac162dc62fc532037df0d98954ab840a97516",
    "https://github.com/psf/requests/tree/c65c780849563c891f35ffc98d3198b71011c012",
    "https://github.com/psf/requests/tree/c65c780849563c891f35ffc98d3198b71011c012",
    "https://github.com/psycopg/psycopg/tree/48a151b805224f090577341e7809cd7fc9fcc3a3",
    "https://github.com/pudo/dataset/tree/b2ab09e58c6f17334e4286009b20887b6a8a8fac",
    "https://github.com/pwaller/pyfiglet/tree/f8c5f35be70a4bbf93ac032334311b326bc61688",
    "https://github.com/py2exe/py2exe/tree/e9c5f0e82a7a634346d87f8e8d2e9732935681a8",
    "https://github.com/pybee/toga/tree/d47833738228f2d59e5478822b4f09ce60a609c6",
    "https://github.com/pybuilder/pybuilder/tree/7a3008e6f0544daeddbcd7125398493b61033357",
    "https://github.com/pyca/cryptography/tree/b0e3a55478a94297c062609eacdb715219658087",
    "https://github.com/pyca/cryptography/tree/b0e3a55478a94297c062609eacdb715219658087",
    "https://github.com/pyca/pynacl/tree/4cae5166b65f0cb877f6c95856044e952b5a0598",
    "https://github.com/PyCQA/flake8/tree/6b6f3d5fefecc994a06f425c18c3cddc9b71e4a4",
    "https://github.com/PyCQA/prospector/tree/520111c261f034472b003519c4d96f483ede8ef5",
    "https://github.com/pydantic/pydantic/tree/103f64da67ad23dfdc7406187db32019a0204d70",
    "https://github.com/pyenv/pyenv/tree/f216b4bfb1598347137ecb3c4a8f893baf9ea37f",
    "https://github.com/pyeve/cerberus/tree/c07c2f942873bd90d333347cb679850a85680aa6",
    "https://github.com/pyeve/eve/tree/c6d61b9f634c2d86f66987984b0025e6982a9400",
    "https://github.com/pyexcel/pyexcel/tree/9dc95a10a368ffbd2035c11639b45c11a0b5fd46",
    "https://github.com/pyglet/pyglet/tree/14a03d72943b324b8934f8dc344138e050201859",
    "https://github.com/pygraphviz/pygraphviz//tree/3ae1b0f002a1d75d396e7deb911aab37569668fe",
    "https://github.com/pyinfra-dev/pyinfra/tree/13e5028f86f240be2e6bbdb173f2ba201c0b4816",
    "https://github.com/pyinstaller/pyinstaller/tree/27ae29f40bc04a9b0508a97a715acd200bddc67f",
    "https://github.com/pyinvoke/invoke/tree/2a8f95fa50e73f1520f8eb0463a8e51321290d98",
    "https://github.com/pylint-dev/pylint/tree/1257474919116196a7059977fcf7e23980009e73",
    "https://github.com/Pylons/colander/tree/4557c017658eb4f6a5dc289078af1a6f850f3f97",
    "https://github.com/Pylons/waitress/tree/ed0149beb3c91def3150ac3cbd57df250a241a9c",
    "https://github.com/pymc-devs/pymc3/tree/ef26ae88e87c2120c2700d062e404ed1f777d358",
    "https://github.com/pymssql/pymssql/tree/e8c0408c27197675d7116beced9e65712389a8af",
    "https://github.com/PyMySQL/mysqlclient/tree/e54e8612957e0d74dafe5d186ba1247a612c81bd",
    "https://github.com/PyMySQL/PyMySQL/tree/01af30fea0880c3b72e6c7b3b05d66a8c28ced7a",
    "https://github.com/pynamodb/PynamoDB/tree/f0bc9171f95ee9a74c32b1bedec762e2012bd8f2",
    "https://github.com/pypa/bandersnatch//tree/3521aa3fd69fc6b4608640898a6e42607ce94737",
    "https://github.com/pypa/setuptools/tree/a82f96dc43cbfb9968b100256cb50702becd614e",
    "https://github.com/pypa/virtualenv/tree/2ec4db5d60d9374a0869703c757ead04a7b67c84",
    "https://github.com/pypa/warehouse/tree/51ffd8ff87d763509486ac3cd03e07cdb92be693",
    "https://github.com/pyparsing/pyparsing/tree/15a106e1bfc7679c5cd3a65c84403061a871a9e6",
    "https://github.com/pyqtgraph/pyqtgraph/tree/f42fa9c49d37f6830dcd4e85707100fc5f90c5d5",
    "https://github.com/PySimpleGUI/PySimpleGUI/tree/2f1bb0509a8d2d06c0757bc8a080f818793b3c43",
    "https://github.com/pyston/pyston//tree/fe8afded6166e0774a62bac627e3fd3ba92a41d2",
    "https://github.com/python-attrs/attrs/tree/755b1778afcee1a323d8efbd25df73da236ab4ab",
    "https://github.com/python-excel/xlrd/tree/0c4e80b3d48dfe2250ac4e514c8231a742fee221",
    "https://github.com/python-excel/xlwt/tree/5a222d0315b6d3ce52a3cedd7c3e41309587c107",
    "https://github.com/python-greenlet/greenlet/tree/4317fba4ba1b393ccfc96458db24cd3f489334ac",
    "https://github.com/python-happybase/happybase/tree/656409902bd6d411950232d50ed541196e993760",
    "https://github.com/python-jsonschema/jsonschema/tree/9472e19ff2b22b2b15ab2688978d5c197b0eea89",
    "https://github.com/python-mode/python-mode/tree/e01c27e8c17b3af2b9df7f6fc5a8a44afc3ad020",
    "https://github.com/python-openxml/python-docx/tree/0cf6d71fb47ede07ecd5de2a8655f9f46c5f083d",
    "https://github.com/python-pillow/Pillow/tree/3c71559804e661a5f727e2007a5be51f26d9af27",
    "https://github.com/python-rapidjson/python-rapidjson/tree/fe21cdc95b76d23f06c15dd9a9845a1f3407f6ad",
    "https://github.com/python-rope/rope/tree/55169bb6f687ee3c0ce76c9230e93b0834acbde5",
    "https://github.com/python-trio/trio/tree/bb63c53681cd27569ecef99201ba38517d8527b0",
    "https://github.com/python/cpython/tree/e7741dd77392ac1fef1e12d86045b0d1d27ec1d9",
    "https://github.com/python/cpython/tree/e7741dd77392ac1fef1e12d86045b0d1d27ec1d9",
    "https://github.com/python/mypy/tree/9e45dadcf6d8dbab36f83d9df94a706c0b4f9207",
    "https://github.com/python/typeshed/tree/1063db7c15135c172f1f6a81d3aff6d1cb00a980",
    "https://github.com/pythonnet/pythonnet/tree/a21c7972809500edd6364003c37695193ac1a5d4",
    "https://github.com/pytoolz/cytoolz//tree/008f5d83b7b066993d820c0b41c8cc6fb583fd19",
    "https://github.com/pytoolz/toolz/tree/08f2604f599847272d801c7f0467451de59fa33a",
    "https://github.com/pytorch/pytorch/tree/70c8047c2d58580a962b00db62f1c70f0e3da328",
    "https://github.com/pytorch/pytorch/tree/70c8047c2d58580a962b00db62f1c70f0e3da328",
    "https://github.com/pytransitions/transitions/tree/7ac51128d53bd02ac8ec0c4144f12993904eed56",
    "https://github.com/quantopian/zipline/tree/014f1fc339dc8b7671d29be2d85ce57d3daec343",
    "https://github.com/quodlibet/mutagen/tree/fbef9b4803c8ad949557aaa4ddced78367006543",
    "https://github.com/r0x0r/pywebview//tree/c69fb10e79e68e91c4f241d73e89e14ea80d7462",
    "https://github.com/RaRe-Technologies/gensim/tree/6591e008f065017adce9d25113a036864e3a9dc6",
    "https://github.com/ray-project/ray//tree/6a06f0ca8eb51c87a07f6ff9d0dd6652f06d1ccf",
    "https://github.com/RaylockLLC/DearPyGui//tree/d3577817fa69d6b5a8b56fde023b0200c0ff83ef",
    "https://github.com/realpython/list-of-python-api-wrappers/tree/82a9fa1dbdc26347cec71cb0e57839c8b4918bdb",
    "https://github.com/redis/redis-py/tree/36619a507addc313c0245bf318e4678938fc5d44",
    "https://github.com/robinhood/faust/tree/14f65ee6f2810ecab3cf3a8888757949dd12dbd8",
    "https://github.com/robotframework/robotframework/tree/37c979c62ca26aa7b6d2a5dfceb10171e881c099",
    "https://github.com/ronaldoussoren/py2app/tree/487a55e34746fa6eb857de51f2bd0ac03026592d",
    "https://github.com/rq/rq/tree/d5f6f57368389e25138a376799458c4be3d94815",
    "https://github.com/rsalmei/alive-progress/tree/35853799b84ee682af121f7bc5967bd9b62e34c4",
    "https://github.com/ryanmcgrath/twython/tree/0c405604285364457f3c309969f11ba68163bd05",
    "https://github.com/s3tools/s3cmd/tree/8cb9b23992714b5ec22c1e514a50996e25aa333b",
    "https://github.com/saffsd/langid.py/tree/4153583eaeeadd88212a69ab5fa61a41283ae59b",
    "https://github.com/saltstack/salt/tree/fb413fc386fbd24b4ed3dd84d883d145b011b56b",
    "https://github.com/sanic-org/sanic/tree/a64d7fe6edb65ac60537f91d4d6c34fe7bc224b9",
    "https://github.com/scanny/python-pptx/tree/278b47b1dedd5b46ee84c286e77cdfb0bf4594be",
    "https://github.com/schematics/schematics/tree/3a144be0aa50f68a4da917e8d957b924dedf9a52",
    "https://github.com/scipy/scipy/tree/da7717ec686eceeb054168ccb31b58a50ec81f74",
    "https://github.com/SciTools/cartopy/tree/1e1583334587ae16644ebb31f1b311b2ef36f23f",
    "https://github.com/SCons/scons/tree/6fee7f921679eb8682c5a688c8d60f37935f6e49",
    "https://github.com/scottrogowski/code2flow/tree/c2c22afe5e12f969cc256373bf8f4eec592dc762",
    "https://github.com/scrapy/scrapy/tree/82acef30517496d622a80f24adb5b3599e63f64a",
    "https://github.com/sdispater/orator/tree/db8744967e1c91a80079ecef70c7db805871dd3d",
    "https://github.com/sdispater/pendulum/tree/fc386be2623f711364c599df3e208eceb4dfa23b",
    "https://github.com/sdispater/poetry/tree/84eeadc21f92a04d46ea769e3e39d7c902e44136",
    "https://github.com/seatgeek/fuzzywuzzy/tree/af443f918eebbccff840b86fa606ac150563f466",
    "https://github.com/seatgeek/sixpack/tree/cce333c04de77f33e5281292b546b846eafc8558",
    "https://github.com/sebastien/cuisine/tree/77e54af2762f6b41fd8351893605bb3158f6a10e",
    "https://github.com/secdev/scapy/tree/0648c0d36ad7e613e7a4014fe89d8829ad50df83",
    "https://github.com/sehmaschine/django-grappelli/tree/94855a1559252b3ac495b11b14abb2563f3c7720",
    "https://github.com/selwin/python-user-agents/tree/5f2d80ab7f9833481089813f48241098679f5f05",
    "https://github.com/sergree/matchering/tree/452cd018e49954e67f7322eeb5bd90d3dca2c030",
    "https://github.com/shahraizali/awesome-django/tree/ed346d06df110764ef3b3643bd3a61f83314bd9f",
    "https://github.com/simonw/datasette/tree/6f7f4c7d89b37187667441ce9df583f6dbbe2977",
    "https://github.com/simonw/sqlite-utils/tree/094b010fd870e9fe9f020d4df200d4de7f27209b",
    "https://github.com/sindresorhus/awesome/tree/22310294d148ba1cc130d3d85623a04620947f54",
    "https://github.com/sirfz/tesserocr/tree/853a885d0154a0345e1ea7db80febe04893a3da8",
    "https://github.com/skorokithakis/shortuuid/tree/6843c128cb334c272954cce8f1dce1e9f9bf4054",
    "https://github.com/sloria/doitlive/tree/69eead7397fca6dce7d2e6c0c5385d85ba8811cb",
    "https://github.com/SmileyChris/django-countries/tree/2547f4de0dba9c858e1875e55f7a9032cb6315f2",
    "https://github.com/sphinx-doc/sphinx//tree/6210799bf5bb9fb5045aaa14465ebfc9fb1c8102",
    "https://github.com/spotify/annoy/tree/8a7e82cb537053926b0ac6ec132b9ccc875af40c",
    "https://github.com/spotify/luigi/tree/0b54a21b0485b50c08b7469c738b0255edc70397",
    "https://github.com/spulec/freezegun/tree/5f171db0aaa02c4ade003bbc8885e0bb19efbc81",
    "https://github.com/spyder-ide/spyder/tree/873dd85ff1c92c718411932acd23446659b8b84d",
    "https://github.com/sqlalchemy/dogpile.cache/tree/2475d0a86949a35907a7f06d247a1cdb6149fd5e",
    "https://github.com/sqlmapproject/sqlmap/tree/9ed5652ae2c031a0fa4d85290b5dc2c3e9760f08",
    "https://github.com/stanfordnlp/stanza/tree/af3d42b70ef2d82d96f410214f98dd17dd983f51",
    "https://github.com/statsmodels/statsmodels/tree/822b3653793bb86584dfecc1cf53844908432593",
    "https://github.com/stchris/untangle/tree/7eec044b6c78f58cc6d8f183b2f9a511bfc334f8",
    "https://github.com/stephenmcd/hot-redis/tree/6b0cf260c775fd98c44b6703030d33004dabf67d",
    "https://github.com/streamlit/streamlit/tree/ec9d236e6ccc865cd81b5dc39d4ab7b456235ce3",
    "https://github.com/sunainapai/makesite/tree/40bb66a10bb7b6cbf9dd9d93b054de95cb20eba6",
    "https://github.com/Suor/django-cacheops/tree/d4b390372d839ff1389662cb311a916eb2c992ed",
    "https://github.com/Suor/funcy/tree/207a7810c216c7408596d463d3f429686e83b871",
    "https://github.com/Supervisor/supervisor/tree/4bf1e57cbf292ce988dc128e0d2c8917f18da9be",
    "https://github.com/sympy/sympy/tree/98f811f58012a904b34299d988f46c836cb79f89",
    "https://github.com/tartley/colorama/tree/136808718af8b9583cb2eed1756ed6972eda4975",
    "https://github.com/tayllan/awesome-algorithms/tree/8a4c0a115550d758bfed29215092020fd51ed058",
    "https://github.com/Tencent/rapidjson/tree/24b5e7a8b27f42fa16b96fc70aade9106cf7102f",
    "https://github.com/tensorflow/tensorflow/tree/83b97e9e8cbc6ac47029d96b17399f6b7434ca20",
    "https://github.com/tensorflow/tensorflow/tree/83b97e9e8cbc6ac47029d96b17399f6b7434ca20",
    "https://github.com/Textualize/rich/tree/8732dc52db3836302657696cd71486dfb61777c7",
    "https://github.com/thauber/django-schedule/tree/0bd4bb32c6802c2d6fed6b2a64e68f4fe2f8c6a4",
    "https://github.com/TheAlgorithms/Python/tree/a2fa32c7ad8085c49021b28578440fc167627e8e",
    "https://github.com/Theano/Theano/tree/7505f23edd66fcdbbe04953f53c650b4d7cec4dd",
    "https://github.com/thumbor/thumbor/tree/b2a6ca86284736ed2c0f69cd52948296406c9297",
    "https://github.com/tiangolo/fastapi/tree/f3bfa3b8a510a6e7aa7f212dfddee50f7a948883",
    "https://github.com/timofurrer/awesome-asyncio/tree/e69f873ad4114c2fdcadf619c7e65d605c227c37",
    "https://github.com/timofurrer/try/tree/a0e3f8d8d52bf5078698b7a4b4418bb7b6850d6b",
    "https://github.com/timothycrosley/isort/tree/342642e36417dfb71c74a2b1de1f6bcfba5b4253",
    "https://github.com/TkTech/pysimdjson/tree/f68fc03b0caf6fde5080697570c1a786c9a23632",
    "https://github.com/tmux-python/tmuxp/tree/696ab8d4f22d75b30e2b457014aaa705af3e369a",
    "https://github.com/tmux/tmux/tree/faf2a448904f4865386319fa11a30ff54d5843f8",
    "https://github.com/tomerfiliba/rpyc/tree/28152fd777c0792743761e5971d2ecd38af6a9b8",
    "https://github.com/TomNicholas/Python-for-Scientists/tree/6e7f996165a52aa65221b21f45ef19698502ece9",
    "https://github.com/tornadoweb/tornado/tree/ae4a4e4feafc631c3dba64c3fbe185d05c37e356",
    "https://github.com/tqdm/tqdm/tree/0ed5d7f18fa3153834cbac0aa57e8092b217cc16",
    "https://github.com/trustedsec/social-engineer-toolkit/tree/43a5702025877acf3482b52c4ba824ece87b02a2",
    "https://github.com/tschellenbach/Stream-Framework/tree/0d604d92f01329dad67b957ff53a894879fe7060",
    "https://github.com/twisted/treq/tree/6291b35ce871216eefa8e21141491ffc1a644375",
    "https://github.com/twisted/twisted/tree/ab7970a1514f7b507698d8bf963c2a67346da962",
    "https://github.com/tyiannak/pyAudioAnalysis/tree/a246ebf4c553db49ed4400e3a902d39c89ec0043",
    "https://github.com/tylerlaberge/PyPattyrn/tree/ca924164b4e7ee2a5d029c41d91cc0b434504aa9",
    "https://github.com/typeddjango/awesome-python-typing/tree/c99cc3c079c361d720a528180ccc33fc1b07f3e5",
    "https://github.com/un33k/python-slugify/tree/872b37509399a7f02e53f46ad9881f63f66d334b",
    "https://github.com/unoconv/unoconv/tree/2d0a3a815e07094aca5ed094fd3825fbe6f0819d",
    "https://github.com/uralbash/awesome-pyramid/tree/b27d8b3ca5d8d5e0a0b9237da79e5fdbb262d542",
    "https://github.com/urllib3/urllib3/tree/98634f7a5a0f39029a21e9f49e9066a8f99a1515",
    "https://github.com/urllib3/urllib3/tree/98634f7a5a0f39029a21e9f49e9066a8f99a1515",
    "https://github.com/Valloric/YouCompleteMe/tree/131b1827354871a4e984c1660b6af0fefca755c3",
    "https://github.com/vandersonmota/model_mommy/tree/52478dd89a3c3218dd93cc9705ce92633e60689b",
    "https://github.com/vinta/pangu.py/tree/ac8b504348e3696997d4b33aa2244e81a15810bd",
    "https://github.com/vispy/vispy/tree/dc070db9927176d8bdb35950d02bd88e9bf851cf",
    "https://github.com/wagtail/wagtail/tree/47fc2008640ece76be97f3d03da224b903a99047",
    "https://github.com/waylan/Python-Markdown/tree/64a3c0fbc00327fbfee1fd6b44da0e5453287fe4",
    "https://github.com/web2py/pydal//tree/faeb5a2eadfa823cafe01d4a174a5f7e507a4197",
    "https://github.com/WhyNotHugo/python-barcode/tree/2f96373fb25939b8fa98e1a9537a0ecfe26eb708",
    "https://github.com/wireservice/csvkit/tree/62c855e098fa2e7b1429d177d57cfe329195cf84",
    "https://github.com/wooey/wooey/tree/dc457291cf3d976f5cfbc15fce71c95a733d3699",
    "https://github.com/worldveil/dejavu/tree/e56a4a221ad204654a191d217f92aebf3f058b62",
    "https://github.com/wsvincent/awesome-django/tree/ed346d06df110764ef3b3643bd3a61f83314bd9f",
    "https://github.com/xonsh/xonsh//tree/5ecdcae86d8d430f125b61a387cf6bb4ab877940",
    "https://github.com/yoloseem/awesome-sphinxdoc/tree/f4fe4afaa98c055188c15515f278579d8eff4a5d",
    "https://github.com/ytdl-org/youtube-dl//tree/a084c80f7bac9ae343075a97cc0fb2c1c96ade89",
    "https://github.com/zappa/Zappa/tree/99c8fbb028c9543ef39f400ae694ad7df48c22a5",
    "https://github.com/ziadoz/awesome-php/tree/cfe9d5d43cb4ddb51b6a84e83cae24a1965e31f1",
    "https://github.com/zoofIO/flexx/tree/ce1eb56f82595f13f89590684627911aafbc4ede",
    "https://github.com/ZoomerAnalytics/xlwings/tree/2011d6bdc54d030f0c0dea9b8c95ae75982df120",
    "https://github.com/zopefoundation/ZODB/tree/f2dc04c998b4e50e5105bc4358140809b8d66b54",
    "https://github.com/ztane/python-Levenshtein//tree/07785f1516ea099ded127bceea71b5fa41147306",
]
DATADOG_MALICIOUS_REPO_URL = (
    "https://github.com/DataDog/malicious-software-packages-dataset.git"
)
MALICIOUS_REPO_URLS = [
    "https://github.com/lxyeternal/pypi_malregistry.git",
    DATADOG_MALICIOUS_REPO_URL,
]
ENCRYPTED_ZIP_PASSWORD = b"infected"  # Password for DataDog encrypted zips

REPO_CACHE_DIR = ".repo_cache"
BENIGN_REPOS_CACHE_PATH = os.path.join(REPO_CACHE_DIR, "benign_repos")
MALICIOUS_REPOS_CACHE_PATH = os.path.join(REPO_CACHE_DIR, "malicious_repos")

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
        choices=["benign", "malicious", "all"],
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

    if args.type in ["benign", "all"]:
        process_benign_repositories(BENIGN_REPO_URLS)

    if args.type in ["malicious", "all"]:
        process_malicious_repositories(MALICIOUS_REPO_URLS)

    logging.info("Script execution finished.")


if __name__ == "__main__":
    main()
