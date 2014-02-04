import sys

import dotconf

_       = sys.argv.pop(0)
modname = sys.argv.pop(0)
install = sys.argv.pop(0)
print "%s in %s" % (modname, install)
mc = dotconf.ModuleConfig(modname, install)
mc.addDirective('CTLogs https://127.0.0.1:9000/log')
mc.save()
