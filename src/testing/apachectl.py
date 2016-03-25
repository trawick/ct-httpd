#!/usr/bin/env python

import os
from subprocess import call
import sys

import yaml

with open('config.yaml') as f:
    config = yaml.load(f)

for tmpdir in ('/tmp/sctaudit', '/tmp/newscts'):
    if not os.path.exists(tmpdir):
        os.mkdir(tmpdir)

print('Using httpd install at %s...' % config['httpd']['install_root'])
call([os.path.join(config['httpd']['install_root'], 'bin', 'apachectl')] + sys.argv[1:])
