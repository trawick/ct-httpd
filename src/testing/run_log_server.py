#!/usr/bin/env python

import os
import subprocess

import yaml

with open('config.yaml') as f:
    config = yaml.load(f)

source_root = config['certificate-transparency']['source_root']
cmd = os.path.join(source_root, 'test', 'run_log_server.sh')
working_directory = os.path.join(source_root, 'test')

print('Using certificate-transparency tools at %s...' % source_root)
p = subprocess.Popen([cmd, '/tmp/logdb', 'testdata/ca-cert.pem'], cwd=working_directory)
p.wait()
