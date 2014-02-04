#!/usr/bin/env python

# import cgi
import os

print "Content-type: text/html"
print

# cgi.print_environ()

t = '<table border="1">\n'
for v in ['HTTPS', 'REMOTE_ADDR', 'REMOTE_PORT', 'SSL_CT_PEER_STATUS', 'SSL_PROTOCOL',
          'SSL_SESSION_RESUMED']:
    t += '''<tr>
  <td>%s</td><td>%s</td>
''' % (v, os.environ.get(v))

t += '</table>\n'
print t


