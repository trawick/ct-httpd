import os

INVALID_MODNAME = "invalid modname"
INVALID_INSTALL = "invalid httpd install dir"

class ModuleConfig:

    def __init__(self, modname, httpd_install):
        if '/' in modname:
            raise Exception("invalid modname")
        if modname[:4] == 'mod_':
            raise Exception("invalid modname")

        self.modname = modname

        self.httpd_install = httpd_install

        self.httpd_confdir = os.path.join(self.httpd_install, 'conf')
        if not os.path.exists(self.httpd_confdir):
            raise Exception(INVALID_INSTALL)

        self.httpd_moduleconfdir = os.path.join(self.httpd_confdir, 'conf.d')
        if not os.path.exists(self.httpd_moduleconfdir):
            raise Exception(INVALID_INSTALL)

        self.config = []
        self.config += ['LoadModule %s_module modules/mod_%s.so' % (self.modname, self.modname)]

    def addDirective(self, d):
        self.config += [d]

    def conf(self):
        return self.config

    def confname(self):
        return os.path.join(self.httpd_moduleconfdir,
                            '%s.conf' % self.modname)

    def save(self):
        f = open(self.confname(), 'w')
        c = self.conf()
        for l in c:
            print >> f, l
        f.close()
