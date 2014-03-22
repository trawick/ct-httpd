#!/usr/bin/env python

import imp
import os
import sqlite3
import sys
import unittest

sys.dont_write_bytecode = True  # wonky since no .py extension
sys.path.append('.')
imp.load_source("ctlogconfig", "ctlogconfig")
import ctlogconfig

db_name = '/tmp/test_db'
public_key_file_1 = 'test-public-key-1.pem'
public_key_file_2 = 'test-public-key-2.pem'

class TestConfigCommand(unittest.TestCase):

    def setUp(self):
        if os.path.exists(db_name):
            os.unlink(db_name)
        ctlogconfig.create_tables(db_name)
        self.cxn = sqlite3.connect(db_name)
        self.cur = self.cxn.cursor()
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 0)

    def tearDown(self):
        ctlogconfig.dump(self.cur, [])
        self.cur.close()
        self.cxn.close()

    def test_url_configuration(self):
        # 1. initial definition
        test_url_1 = 'https://log.example.com/foo'
        test_url_2 = test_url_1 + 'XX'
        ctlogconfig.configure_url(self.cur, [test_url_1])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.id, 1)
        self.assertEqual(rec.log_id, None)
        self.assertEqual(rec.public_key, None)
        self.assertEqual(rec.distrusted, None)
        self.assertEqual(rec.min_valid_timestamp, None)
        self.assertEqual(rec.max_valid_timestamp, None)
        self.assertEqual(rec.url, test_url_1)
        # 2. update URL of existing record
        ctlogconfig.configure_url(self.cur, ['#1', test_url_2])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.id, 1)
        self.assertEqual(rec.log_id, None)
        self.assertEqual(rec.public_key, None)
        self.assertEqual(rec.distrusted, None)
        self.assertEqual(rec.min_valid_timestamp, None)
        self.assertEqual(rec.max_valid_timestamp, None)
        self.assertEqual(rec.url, test_url_2)

    def test_key_configuration(self):
        # 1. Configure public key (new entry)
        ctlogconfig.configure_public_key(self.cur,
                                         [public_key_file_1])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.id, 1)
        self.assertEqual(rec.log_id, None)
        self.assertEqual(rec.public_key, public_key_file_1)
        self.assertEqual(rec.distrusted, None)
        self.assertEqual(rec.min_valid_timestamp, None)
        self.assertEqual(rec.max_valid_timestamp, None)
        self.assertEqual(rec.url, None)
        # 2. update public key of existing record
        ctlogconfig.configure_public_key(self.cur,
                                         ['#1', public_key_file_2])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.id, 1)
        self.assertEqual(rec.public_key, public_key_file_2)

    def test_forget(self):
        # 1. Configure public key (new entry)
        ctlogconfig.configure_public_key(self.cur,
                                         [public_key_file_1])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 1)
        ctlogconfig.forget_log(self.cur, ['#1'])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 0)

    def test_time_range(self):
        log_id_1 = 'C0FE' * 16
        ctlogconfig.time_range(self.cur, [log_id_1, '-', 9999])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.id, 1)
        self.assertEqual(rec.log_id, log_id_1)
        self.assertEqual(rec.public_key, None)
        self.assertEqual(rec.distrusted, None)
        self.assertEqual(rec.min_valid_timestamp, None)
        self.assertEqual(rec.max_valid_timestamp, 9999)
        self.assertEqual(rec.url, None)

        ctlogconfig.time_range(self.cur, ['#1', 8888, 9999])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.id, 1)
        self.assertEqual(rec.log_id, log_id_1)
        self.assertEqual(rec.public_key, None)
        self.assertEqual(rec.distrusted, None)
        self.assertEqual(rec.min_valid_timestamp, 8888)
        self.assertEqual(rec.max_valid_timestamp, 9999)
        self.assertEqual(rec.url, None)

    def test_trust_distrust(self):
        log_id_1 = 'C0FE' * 16
        ctlogconfig.trust_log(self.cur, [log_id_1])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.id, 1)
        self.assertEqual(rec.log_id, log_id_1)
        self.assertEqual(rec.public_key, None)
        self.assertEqual(rec.distrusted, 0)
        self.assertEqual(rec.min_valid_timestamp, None)
        self.assertEqual(rec.max_valid_timestamp, None)
        self.assertEqual(rec.url, None)

        ctlogconfig.distrust_log(self.cur, ['#1'])
        recs = ctlogconfig.dump_ll(self.cur)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.id, 1)
        self.assertEqual(rec.log_id, log_id_1)
        self.assertEqual(rec.public_key, None)
        self.assertEqual(rec.distrusted, 1)
        self.assertEqual(rec.min_valid_timestamp, None)
        self.assertEqual(rec.max_valid_timestamp, None)
        self.assertEqual(rec.url, None)
        
        
if __name__ == '__main__':
    unittest.main()
