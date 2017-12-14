# -*- coding:utf-8 -*-

""" 
NW Scan Data Format between Scanner and Controller
"""

import datetime
import re


class PortScanInput:
    def __init__(self, addr, port):
        self._set_addr(addr)
        self._set_port(port)

    @property
    def addr(self):
        return self._addr

    @addr.setter
    def addr(self, addr):
        self._set_addr(addr)

    def _set_addr(self, addr):
        if not type(addr) == str:
            raise Exception("Input Type Error. %s (<addr>) must be String.)" % (addr))
        elif not re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", addr):
            raise Exception("Input Type Error. %s (<addr>) must be like 192.168.1.1."
                            % (addr))
        self._addr = addr

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, port):
        self._set_port(self, port)

    def _set_port(self, port):
        if not type(port) == int:
            raise Exception("Input Type Error. %s(<port>) must be integer." % port)
        elif not (0 < port and port <= 256*256):
            raise Exception("Input Type Error. %s(<port>) must be 0 < port <= 65536" % port)

        self._port = port


class PortScanOutput:
    def __init__(self, scantime, result, desc):
        self._set_scantime(scantime)
        self._set_result(result)
        self._set_desc(desc)

    @property
    def scantime(self):
        return self._scantime

    @scantime.setter
    def scantime(self, scantime):
        self._set_scantime(scantime)

    def _set_scantime(self, scantime):
        if not type(scantime) == datetime.datetime:
            raise Exception("Input Type Error. %s(<scantime>) must be datetime.datetime." % (scantime))
        self._scantime = scantime

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, result):
        self._set_result(result)

    def _set_result(self, result):
        candidate = ["open", "close", "error"]
        if not type(result) == str:
            raise Exception("Input Type Error. %s(<result>) must be str" % (result))
        elif not result in candidate:
            raise Exception("Input Type Error. %s(<result>) must be %s" %
                            (result, " or ".candidate))
        self._result = result

    @property
    def desc(self):
        return self._desc

    @desc.setter
    def desc(self, desc):
        self._set_desc(desc)

    def _set_desc(self, desc):
        if not type(desc) == str:
            raise Exception("Input Type Error. %s(<desc>) must be String." % (desc))


class PasswordScanInput:
    def __init__(self, addr, proto, account, password):
        self._set_addr(addr)
        self._set_proto(proto)
        self._set_account(account)
        self._set_password(password)

    @property
    def addr(self):
        return self._addr

    @addr.setter
    def addr(self, addr):
        self._set_addr(addr)

    def _set_addr(self, addr):
        if not type(addr) == str:
            raise Exception("Input Type Error. %s (<addr>) must be String.)" % (addr))
        elif not re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", addr):
            raise Exception("Input Type Error. %s (<addr>) must be like 192.168.1.1."
                            % (addr))
        self._addr = addr

    @property
    def proto(self):
        return self._proto

    @proto.setter
    def proto(self, proto):
        self._set_proto(proto)

    def _set_proto(self, proto):
        candidate = ["ssh", "rdp"]
        if not type(proto) == str:
            raise Exception("Input Type Error. %s(<proto>) must be String." % (proto))
        elif not proto in candidate:
            raise Exception("Input Type Error. %s(<proto>) must be %s." % (proto, " or ".join(candidate)))

        self._proto = proto

    @property
    def account(self):
        return self._account

    @account.setter
    def account(self, account):
        self._set_account(account)

    def _set_account(self, account):
        if not type(account) == str:
            raise Exception("Input Type Error. %s(<account>) must be String." % (account))

        self._account = account

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._set_password(password)

    def _set_password(self, password):
        if not type(password) == str:
            raise Exception("Input Type Error. %s(<password>) must be String." % (password))

        self._password = password


class PasswordScanOutput:
    def __init__(self, scantime, result, desc):
        self._set_scantime(scantime)
        self._set_result(result)
        self._set_desc(desc)

    @property
    def scantime(self):
        return self._scantime

    @scantime.setter
    def scantime(self, scantime):
        self._set_scantime(scantime)

    def _set_scantime(self, scantime):
        if not type(scantime) == datetime.datetime:
            raise Exception("Input Type Error. %s(<scantime>) must be datetime.datetime." % (scantime))
        self._scantime = scantime

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, result):
        self._set_result(result)

    def _set_result(self, result):
        candidate = ["open", "close", "error"]
        if not type(result) == str:
            raise Exception("Input Type Error. %s(<result>) must be str" % (result))
        elif not result in candidate:
            raise Exception("Input Type Error. %s(<result>) must be %s" %
                            (result, " or ".candidate))
        self._result = result

    @property
    def desc(self):
        return self._desc

    @desc.setter
    def desc(self, desc):
        self._set_desc(desc)

    def _set_desc(self, desc):
        if not type(desc) == str:
            raise Exception("Input Type Error. %s(<desc>) must be String." % (desc))

class SMTPScanInput:
    def __init__(self, addr, mailaddr):
        self._set_addr(addr)
        self._set_mailaddr(mailaddr)

    @property
    def addr(self):
        return self._addr

    @addr.setter
    def addr(self, addr):
        self._set_addr(addr)

    def _set_addr(self, addr):
        if not type(addr) == str:
            raise Exception("Input Type Error. %s (<addr>) must be String.)" % (addr))
        elif not re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", addr):
            raise Exception("Input Type Error. %s (<addr>) must be like 192.168.1.1."
                            % (addr))
        self._addr = addr

    @property
    def mailaddr(self):
        return self._mailaddr

    @mailaddr.setter
    def mailaddr(self, mailaddr):
        self._set_mailaddr(mailaddr)

    def _set_mailaddr(self, mailaddr):
        if not type(mailaddr) == str:
            raise Exception("Input Type Error. %s(<mailaddr>) must be String." % (mailadd))

        self._mailaddr = mailaddr


class SMTPScanOutput:
    def __init__(self, scantime, result, desc):
        self._set_scantime(scantime)
        self._set_result(result)
        self._set_desc(desc)

    @property
    def scantime(self):
        return self._scantime

    @scantime.setter
    def scantime(self, scantime):
        self._set_scantime(scantime)

    def _set_scantime(self, scantime):
        if not type(scantime) == datetime.datetime:
            raise Exception("Input Type Error. %s(<scantime>) must be datetime.datetime." % (scantime))
        self._scantime = scantime

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, result):
        self._set_result(result)

    def _set_result(self, result):
        candidate = ["open", "close", "error"]
        if not type(result) == str:
            raise Exception("Input Type Error. %s(<result>) must be str" % (result))
        elif not result in candidate:
            raise Exception("Input Type Error. %s(<result>) must be %s" %
                            (result, " or ".candidate))
        self._result = result

    @property
    def desc(self):
        return self._desc

    @desc.setter
    def desc(self, desc):
        self._set_desc(desc)

    def _set_desc(self, desc):
        if not type(desc) == str:
            raise Exception("Input Type Error. %s(<desc>) must be String." % (desc))
