import os
import dotconf

modname = 'ssl_ct'
install = os.path.join('home', 'trawick', 'inst', '25-64')

for bad_modname in ['mod_ssl_ct', '/ssl_ct']:
    try:
        mc = dotconf.ModuleConfig('mod_ssl_ct', install)
    except Exception as e:
        assert e.args[0] == dotconf.INVALID_MODNAME

try:
    mc = dotconf.ModuleConfig(modname, '/tmp')
except Exception as e:
    assert e.args[0] == dotconf.INVALID_INSTALL
