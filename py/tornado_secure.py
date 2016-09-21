# coding: utf-8
"""
    Module tornado_secure for getting secured values we must reach
"""
from __future__ import unicode_literals, division, absolute_import
__author__ = 'Rasklad.com (P) 2016'

import sys
print('Python', sys.version_info)

import pytest
from tornado import web
# from tornado.util import u

#

@pytest.fixture()
def skey():
    return 'secure_key'

#

def test_en_de_v2(skey):
    encoded = web.create_signed_value(skey, 'some', 'value')
    # print(encoded) #D
    decoded = web.decode_signed_value(skey, 'some', encoded)
    assert decoded == 'value'


def test_de_v2(skey):
    encoded = '2|1:0|10:1474429838|4:some|8:dmFsdWU=|bf3d274f65723ddb8ce27c74b1c5fa76def0bffa27b583f2887bf6c7e9fc4016'
    decoded = web.decode_signed_value(skey, 'some', encoded)
    assert decoded == 'value'
