#!/usr/bin/env python
# Auther L
# Date 2017-10-01
# Version 1.0.1

from __future__ import print_function, unicode_literals
from socket import AF_INET, AF_INET6, inet_ntop, inet_pton, gethostbyname, htonl
from functools import partial
from itertools import compress
import csv
import argparse
import re
import random
import time
import sys
import os
import struct
import difflib
import io
import pwd
import copy
import platform


class LLK(object):
    def __init__(self, args):
        self.default_logpath = {
            'wtmp': '/var/log/',
            'utmp': '/var/run/',
            'btmp': '/var/log/',
            'lastlog': '/var/log/'
        }
        self.logs_fmt = {
            'wtmp': 'hi32s4s32s256shhiii16s20x',
            'utmp': 'hi32s4s32s256shhiii16s20x',
            'btmp': 'hi32s4s32s256shhiii16s20x',
            'lastlog': 'I32s256s'
        }
        Xtmp_head = ['TYPE', 'PID', 'TTY', 'tty', 'USER', 'HOST', 'T', 'E', 'S', 'TIME', 'MS', 'IP']
        self.log_head = {
            'wtmp': Xtmp_head,
            'utmp': Xtmp_head,
            'btmp': Xtmp_head,
            'lastlog': ['UID', 'USER', 'TIME', 'TTY', 'IP']
        }
        try:
            for attr in dir(args):
                if attr.startswith('TIME'):
                    value = getattr(args, attr)
                    if value:
                        timestamp = self.date2timestamp(value)
                        setattr(args, attr, timestamp)
        except:
            raise SystemExit('[!] TIME is wrong format')
        self.args = args


    @staticmethod
    def _parse_log(fmt, path):
        def clean_x00(l):
            l = list(l)
            new = []
            if fmt.endswith('20x'):
                if l[-1][4:] == b'\x00'*12:
                    af = AF_INET 
                    ip_bytes = l[-1][:4]
                else:
                    af = AF_INET6
                    ip_bytes = l[-1]
                l[-1] = inet_ntop(af, ip_bytes)
            for c in l:
                if isinstance(c, bytes):
                    try:
                        c = c.replace(b'\x00', b'').decode()
                    except:
                        c = '< TTY >'
                new.append(c)
            return new

        fmt_size = struct.calcsize(fmt)
        result = []
        try:
            with open(path, 'rb') as f:
                records = iter(partial(f.read, fmt_size), b'')
                for r in records:
                    r = struct.unpack(fmt, r)
                    result.append(clean_x00(r))
        except Exception as e:
            raise SystemExit(e)
        return result


    def _get_logpaths(self, logname):
        def order_func(name):
            spacer = '.'
            if spacer in name:
                return int(name.split(spacer)[1])
            else:
                return 0

        log_dir = self.default_logpath[logname]
        re_logname = re.compile(r'{}(\.\d+)?$'.format(logname))
        lognames = (os.path.join(log_dir, name) for name in os.listdir(log_dir) if re_logname.match(name))
        return reversed(sorted(lognames, key=order_func))


    def _get_log(self, logname):
        fmt = self.logs_fmt[logname]
        result = []

        if hasattr(self.args, 'f') and self.args.f:
            path = self.args.f
            records = self._parse_log(fmt, path)
            result.extend(records)
        else:
            for filename in self._get_logpaths(logname):
                records = self._parse_log(fmt, filename)
                result.extend(records)
        return result


    @staticmethod
    def timestamp2date(timestamp):
        return time.strftime("%y/%m/%d %H:%M:%S", time.localtime(timestamp))


    @staticmethod
    def date2timestamp(timestr):
        timestr = timestr.strip()
        if '-' in timestr:
            fmt = '%y/%m/%d-%H:%M' if timestr.count(':') == 1 else '%y/%m/%d-%H:%M:%S'
        else:
            fmt = '%y/%m/%d %H:%M' if timestr.count(':') == 1 else '%y/%m/%d %H:%M:%S'
        return int(time.mktime(time.strptime(timestr, fmt)))


    @staticmethod
    def SQL_print(head, result, highlight, io):
        widths = list(map(len, head))
        for line in result:
            widths = list(map(lambda x,y: max(x,len(str(y))), widths, line))
        dividingLine = ('+-{}-'*len(head)+'+').format(*('-'*i for i in widths))
        widths_dict = {'_'+str(i):v for i, v in enumerate(widths)}
        line_str = '|' + ''.join(' {:<{_%s}} |' % i for i in range(len(widths)))
        print(dividingLine, file=io)
        print(line_str.format(*head, **widths_dict), file=io)
        print(dividingLine, file=io)
        for i, line in enumerate(result):
            content = line_str.format(*line, **widths_dict)
            if highlight and not highlight[i]:
                content = '\033[1;31m' + content + '*' + '\033[0;37m'
            print(content, file=io)
        print(dividingLine + '\n', file=io)


    @staticmethod
    def select_records_columns(cols, head, records):
        select = lambda x, f: [ x[i] for i in f ]
        cols_num = [ head.index(c) for c in cols ]
        head = select(head, cols_num)
        rs = []
        for r in records:
            rs.append(select(r, cols_num))
        return head, rs


    @staticmethod
    def select_records_lines(args, head, records, turn):
        lines_bool = [True] * len(records)
        a_dict = args.__dict__
        select_key = set(a_dict.keys()) & set(head)
        select_args = { k:a_dict[k] for k in select_key if a_dict[k] }
        for k, v in select_args.items():
            index = head.index(k)
            for no, r in enumerate(records):
                if r[index] != v:
                    lines_bool[no] = False
        time_col = head.index('TIME')
        for no, r in enumerate(records):
            T = r[time_col]
            if (args.TIME_S and args.TIME_S > T) or (args.TIME_E and args.TIME_E < T):
                    lines_bool[no] = False
        if turn:
            lines_bool = map(lambda x: not x, lines_bool)
        return compress(records, lines_bool)

            
    def _print_log(self, records, logname, highlight=None, io=sys.stdout):
        records = copy.deepcopy(records)
        if logname in ('wtmp', 'utmp', 'btmp'):
            head = self.log_head[logname]
            records = self.select_records_lines(self.args, head, records, self.args.r)
            result = []
            for r in records:
                r[-3] = self.timestamp2date(r[-3])
                result.append(r)
            if not self.args.a:
                cols = ['TYPE', 'PID', 'TTY', 'USER', 'HOST', 'TIME']
                head, result = self.select_records_columns(cols, head, result)
        elif logname == 'lastlog':
            head = self.log_head[logname]
            result = []
            for uid, r in enumerate(records):
                if r[0]:
                    try:
                        user = pwd.getpwuid(uid).pw_name
                    except:
                        user = ''
                    r[0] = self.timestamp2date(r[0])
                    r = [uid, user] + r
                    result.append(r)
            result = list(self.select_records_lines(self.args, head, result, self.args.r))
        if result:
            if not highlight:
                print('\n[+] "{}" log. ({} rows)'.format(logname, len(result)), file=io)
            self.SQL_print(head, result, highlight, io)


    @staticmethod
    def _check_legal(logname, records):
        def check(limit, value):
            if limit == None:
                return True
            elif limit == value:
                return True
            elif isinstance(limit, tuple) and value in range(*limit):
                return True
            return False

        with open('/proc/sys/kernel/pid_max') as f:
            pid_max = int(f.read().strip())
        release = platform.release()

        pid_range = (300, pid_max)
        type_legal = {
            1: [1, (0, 300), '~', '~~', None, release, 0, 0, 0, None, None, '0.0.0.0'],
            2: [2, 0, '~', '~~', None, release, 0, 0, 0, None, None, '0.0.0.0'],
            5: [5, pid_range, None, None, '', '', 0, 0, pid_range, None, None, '0.0.0.0'],
            6: [6, pid_range, None, None, None, None, 0, 0, None, None, None, None],
            7: [7, pid_range, None, None, None, None, 0, 0, None, None, None, None],
            8: [8, (0, pid_max), None, None, None, '', None, None, None, None, None, '0.0.0.0']
        }
        legal_records = []
        previous_time = 0
        previous_ms = 0
        for r in records:
            _type, _pid, _tty, _ttys, _user, _host, _T, _E, _S, _time, _ms, _ip = r

            if _type in type_legal:
                legal = type_legal[_type]
                result = all(map(check, legal, r))
            else:
                print('[*] Discovery new type record: {}'.format(r))
                result = True

            if logname == 'btmp':
                if _type not in (6, 7):
                    result = False

            if result:
                if (_time > previous_time or (_time == previous_time and _ms > previous_ms)) or \
                    (_type == 6 and _time == previous_time and _ms == previous_ms):
                    previous_time = _time
                    previous_ms = _ms
                else:
                    if not (logname == 'wtmp' and _type == 6 and _time == previous_time):
                        result = False

            if result:
                if _type == 7:
                    if logname == 'btmp':
                        if not _tty.startswith('tty') or not _ttys or _host or _ip != '0.0.0.0':
                            result = False
                    else:
                        if _host == ':0':
                            if _ip != '0.0.0.0' or not _tty.startswith('tty'):
                                result = False
                        elif _host == ':0.0':
                            if _ttys == '' or _ip != '0.0.0.0':
                                result = False
                        elif _host == '':
                            if _ttys or _ip != '0.0.0.0':
                                result = False
                        else:
                            if gethostbyname(_host) != _ip:
                                result = False
                elif _type == 6:
                    if _ttys:
                        if _host or _pid != _S or _ip != '0.0.0.0':
                            result = False
                    else:
                        if _ms or gethostbyname(_host) != _ip:
                            result = False
                elif _type == 8:
                    if _user:
                        if _ttys == '' or _T or _E or _S:
                            result = False
                    elif _ttys.startswith('tty'):
                        if not (_T and _E and _S):
                            result = False
                    else:
                        if _T or _E or _S:
                            result = False

            legal_records.append(result)
        return legal_records


    def _check_Xtmp(self, logname):
        records = self._get_log(logname)
        legal_records = self._check_legal(logname, records)
        if all(legal_records):
            print('\n[+] [ {} ] No format and logic issues found'.format(logname))
        else:
            print('\n[-] [ {}, {} errers ] Find format or logical problem'.format(logname, legal_records.count(False)))
            self._print_log(records, logname, legal_records)
        return records, all(legal_records)


    @staticmethod
    def _create_utmp(wtmp_log):
        wtmp_log = copy.deepcopy(wtmp_log)
        for i, r in enumerate(reversed(wtmp_log)):
            if r[0] == 2:
                index = len(wtmp_log) - 1 - i
                break
        else:
            index = 0
        utmp_log = []
        ttys = []
        for r in wtmp_log[index:]:
            tty = r[2]
            if r[0] in (1, 2):
                utmp_log.append(r)
                ttys.append('')
            else:
                if tty in ttys:
                    index = ttys.index(tty)
                    if r[0] == 8:
                        r[3] = utmp_log[index][2][-4:]
                        r[-1] = utmp_log[index][-1]
                    elif r[0] == 7 and r[3] == '':
                        r[3] = utmp_log[index][2][-4:]
                        r[-4] = utmp_log[index][1]
                    utmp_log[index] = r
                else:
                    ttys.append(tty)
                    utmp_log.append(r)
        return utmp_log


    @staticmethod
    def _create_lastlog(wtmp_log):
        uid_list = []
        lastlog_tmp = []
        for r in wtmp_log:
            tty = r[2]
            user = r[4]
            ip = r[-1]
            time = r[-3]
            if r[0] == 7:
                try:
                    uid = pwd.getpwnam(user).pw_uid
                except:
                    print('[!] No this user: {}'.format(user))
                    continue
                record = (uid, [time, tty, ip])
                if user in uid_list:
                    index = uid_list.index(uid)
                    lastlog_tmp[index] = record
                else:
                    lastlog_tmp.append(record)
                    uid_list.append(uid)
        lastlog_log = [[0, '', '']] * (max(uid_list) + 1)
        for uid, record in lastlog_tmp:
            lastlog_log[uid] = record
        return lastlog_log


    def _create_login_log(self, wtmp_log):
        utmp_log = self._create_utmp(wtmp_log)
        lastlog_log = self._create_lastlog(wtmp_log)
        return utmp_log, lastlog_log


    def _merge_log(self, utmp_log, lastlog_log):
        self.args.a = True
        with io.StringIO() as log_output:
            self._print_log(lastlog_log, 'lastlog', io=log_output)
            self._print_log(utmp_log, 'utmp', io=log_output)
            output = log_output.getvalue()
        return output


    def _compress_log(self, new_log, old_log):
        a, b = new_log.splitlines(True), old_log.splitlines(True)
        if list(difflib.context_diff(a, b)):
            diff_html = difflib.HtmlDiff()
            output_file = self.args.HTML_NAME
            with open(output_file, 'w') as f:
                f.write(diff_html.make_file(a, b))
            print('\n[+] [ utmp & lastlog ] Difference report: "{}"'.format(output_file))
        else:
            print('\n[+] [ utmp & lastlog ] No Format and logic issues found')


    def _write2file(self, logname, logpath, records):
        type_name = str if sys.version_info.major == 3 else unicode
        def str2bytes(l, logname):
            if logname != 'lastlog':
                ip6 = (r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|'
                       r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|'
                       r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|'
                       r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|'
                       r'(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|'
                       r'(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|'
                       r'(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4})'
                       r'{1,7}\Z)|(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]'
                       r'?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
                       r'(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|'
                       r'[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|'
                       r'(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|'
                       r'[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|'
                       r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|'
                       r'2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d))'
                       r'{3}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:'
                       r'(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?'
                       r'\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4})'
                       r'{1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|'
                       r'[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]'
                       r'{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|'
                       r'2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A(([0-9a-f]{1,4}:){1,5}|:):'
                       r'(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?'
                       r'\d?\d)){3}\Z)|(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|'
                       r'[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)')
                ip4 = (r'^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|'
                       r'[0-1]?\d?\d)){3}$')
                if not l[-1]:
                    l[-1] = b''
                elif re.match(ip4, l[-1]):
                    af = AF_INET
                elif re.match(ip6, l[-1]):
                    af = AF_INET6
                else:
                    raise SystemExit('[!] IP format error: {}'.format(repr(l[-1])))
                if l[-1]:
                    l[-1] = inet_pton(af, l[-1])
            r = []
            for c in l:
                if isinstance(c, type_name):
                    c = c.encode()
                r.append(c)
            return r
        atime = os.popen('stat -c %x {}'.format(logpath)).read().strip()
        mctime = os.popen('stat -c %y {}'.format(logpath)).read().strip()
        logfmt = self.logs_fmt[logname]
        with open(logpath, 'wb') as f:
            for r in records:
                r = str2bytes(r, logname)
                f.write(struct.pack(logfmt, *r))
        if self.args.ignore_ctime:
            cmd = 'touch -a --date "{2}" "{0}" && touch -m --date "{1}" "{0}"'
        else:
            cmd = ('LLK_NOW=`date` && touch -a --date "{2}" "{0}" && '
                   'date -s "{1}" && touch -m --date "{1}" "{0}" && '
                   'date -s "$LLK_NOW" && unset LLK_NOW')
        os.popen(cmd.format(logpath, mctime, atime)).read()


    def _write_log(self, logname, records):
        records = copy.deepcopy(list(records))
        file2records_index = []
        for logpath in self._get_logpaths(logname):
            file_last_timestamp = os.stat(logpath).st_mtime
            file2records_index.append([logpath, file_last_timestamp, list()])
        
        time_index = 0 if logname == 'lastlog' else -3
        file2records_index[-1][1] = float('inf')
        index = 0
        ii_max = len(records) - 1
        for i, (_, timestamp, file_rs) in enumerate(file2records_index):
            for ii, r in enumerate(records[index:]):
                time = r[time_index]
                if time <= timestamp:
                    file_rs.append(r)
                    if ii == ii_max:
                        index = ii_max + 1
                else:
                    index = ii
                    break

        for logpath, _, rs in file2records_index:
            self._write2file(logname, logpath, rs)


    def _compress_mtime_ctime(self):
        for log in ('btmp', 'wtmp', 'lastlog', 'utmp'):
            for logpath in self._get_logpaths(log):
                log_stat = os.stat(logpath)
                if log_stat.st_mtime != log_stat.st_ctime:
                    print('[!] [ {} ] ctime & mtime Inconsistent!'.format(logpath))
                fmt = self.logs_fmt[log]
                time_index = 0 if log == 'lastlog' else -3
                records = self._parse_log(fmt, logpath)
                log_mtime = int(log_stat.st_mtime)
                if records:
                    if log == 'lastlog':
                        last_time = max(records, key=lambda x: x[0])[0]
                    else:
                        last_time = records[-1][time_index]
                    if last_time != log_mtime:
                        print('[-] [ {} ] Log is tampered with!!'.format(logpath))


    def text2record(self, text, logname):
        d2t = self.date2timestamp
        if logname == 'lastlog':
            v_type = [int, str, d2t, str, str]
        else:
            v_type = [int, int, str, str, str, str, int, int, int, d2t, int, str]

        spacer_count = len(v_type) + 1
        for line in text.splitlines():
            if line.count('|') == spacer_count:
                str_list = [i.strip() for i in line.split('|') if i]
                try:
                    yield [func(v) for func, v in zip(v_type, str_list)]
                except:
                    continue


    def check_log(self):
        self.args.r = False
        self.args.USER = self.args.PID = self.args.TIME = None 
        self.args.HOST = self.args.TIME_E = self.args.TIME_S = None
        self._compress_mtime_ctime()
        self._check_Xtmp('btmp')
        wtmp_log, wtmp_legal_bool = self._check_Xtmp('wtmp')
        if wtmp_legal_bool:
            old_utmp = self._get_log('utmp')
            old_lastlog = self._get_log('lastlog')
            new_utmp, new_lastlog = self._create_login_log(wtmp_log)
            new_log = self._merge_log(new_utmp, new_lastlog)
            old_log = self._merge_log(old_utmp, old_lastlog)
            self._compress_log(new_log, old_log)


    def list_log(self):
        logname = self.args.logname
        if logname == 'all':
            for ln in ('lastlog', 'utmp', 'btmp', 'wtmp'):
                records = self._get_log(ln)
                self._print_log(records, ln)
        else:
            records = self._get_log(logname)
            self._print_log(records, logname)


    def delete_log(self):
        self.args.r = not self.args.r
        logname = 'btmp'
        records = self._get_log(logname)
        head = self.log_head[logname]
        records = self.select_records_lines(self.args, head, records, self.args.r)
        self._write_log(logname, records)


    def add_log(self):
        logname = 'btmp'
        with open('/proc/sys/kernel/pid_max') as f:
            pid_max = int(f.read().strip())
        _user = self.args.USER or 'root'
        _pid = self.args.PID or random.randrange(300, pid_max)
        _ms = self.args.MS or random.randrange(1e4, 1e6)
        _tty = self.args.TTY or 'tty' + str(random.randrange(1, 8))
        _ip = self.args.IP or inet_ntop(AF_INET, struct.pack('I', htonl(random.getrandbits(32))))
        _time = self.args.TIME
        records = {6: [6, _pid, 'ssh:notty', '', _user, _ip, 0, 0, 0, _time, 0, _ip],
                   7: [7, _pid, _tty, _tty, _user, '', 0, 0, _pid, _time, _ms, '0.0.0.0']}
        add_record = records[self.args.TYPE]
        records = self._get_log(logname)
        for i, r in enumerate(records):
            if _time < r[-3] or (_time == r[-3] and _ms < r[-2]):
                records.insert(i, add_record)
                break
        else:
            records.append(add_record)
        self._write_log(logname, records)


    def modify_log(self):
        logname = self.args.logname
        records = self._get_log(logname)
        user = self.args.USER
        host = self.args.HOST
        pid = self.args.PID
        time = self.args.TIME
        start = self.args.TIME_S
        end = self.args.TIME_E
        for r in records:
            T = r[-3]
            time_in_range = True
            if time and T != time:
                time_in_range = False
            if (start and T < start) or (end and T > end):
                time_in_range = False
            if (user and user != r[4]) or (pid and pid != r[1]) or (host and host != r[5]):
                time_in_range = False
            if time_in_range:
                if self.args.TO_USER and r[4] and r[4] != 'LOGIN':
                    r[4] = self.args.TO_USER
                if self.args.TO_HOST and r[5] == r[-1]:
                    r[5] = r[-1] = self.args.TO_HOST
                if self.args.TO_PID:
                    r[1] = self.args.TO_HOST
        self._write_log(logname, records)
        if logname == 'wtmp':
            new_utmp, new_lastlog = self._create_login_log(records)
            self._write_log('utmp', new_utmp)
            self._write_log('lastlog', new_lastlog)


    def export_log(self):
        self.args.a = True
        self.args.r = False
        self.args.USER = self.args.PID = self.args.TIME = None 
        self.args.HOST = self.args.TIME_E = self.args.TIME_S = None
        logname = self.args.logname
        records = self._get_log(logname)
        with io.StringIO() as log_output:
            self._print_log(records, logname, io=log_output)
            data = re.sub(r'\(.*? rows\)', '', log_output.getvalue())
        suffix = '.csv' if self.args.csv else '.txt'
        filename = self.args.FILE or logname + suffix
        with open(filename, 'w') as f:
            if self.args.csv:
                csvObj = csv.writer(f)
                head = self.log_head[logname]
                csvObj.writerow(head)
                for r in self.text2record(data, logname):
                    csvObj.writerow(r)
            else:
                f.write(data)
        print('[+] Write {} log to "{}".'.format(logname, filename))


    def import_log(self):
        logname = self.args.logname
        records = []
        with open(self.args.input_file) as f:
            iscsv = bool(f.readline().count(',') == 11)
            if iscsv:
                v_type = [int, int, str, str, str, str, int, int, int, int, int, str]
                read = csv.reader(f)
                for l in read:
                    r = [func(v) for func, v in zip(v_type, l)]
                    records.append(r)
            else:
                for r in self.text2record(f.read(), logname):
                    records.append(r)

        self._write_log(logname, records)
        if logname == 'wtmp':
            new_utmp, new_lastlog = self._create_login_log(records)
            self._write_log('utmp', new_utmp)
            self._write_log('lastlog', new_lastlog)


def commandline():
    cmds = ['list', 'check', 'add', 'delete', 'modify', 'import', 'export']
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        help_msg = '''usage: llk.py <command> [options] [-h]

<Commands>
  list      Print log
  check     Check log
  add       Add log    (only btmp)
  delete    Delete log (only btmp)
  modify    Modify log (only wtmp & btmp)
  import    Import log (only wtmp & btmp)
  export    Export log
'''
        raise SystemExit(help_msg)

    cmd = sys.argv[1]
    parser = argparse.ArgumentParser(
                usage='%(prog)s {} [options]'.format(cmd))
    if cmd == 'list':
        lognames = ('all', 'wtmp', 'utmp', 'btmp', 'lastlog')
        if len(sys.argv) == 2 or (len(sys.argv) > 2 and sys.argv[2] not in lognames):
            sys.argv.insert(2, 'all')
        parser.add_argument('logname', choices=lognames, help='Log name [default:all]')
        parser.add_argument('-r', action='store_true', help='Reserve select records')
        parser.add_argument('-a', action='store_true', help='Show all columns')
        parser.add_argument('-f', metavar='LogFile', help='Specify log file path')
        parser.add_argument('-type', type=int, dest='TYPE', help='TYPE')
        parser.add_argument('-pid', type=int, dest='PID', help='PID')
        parser.add_argument('-tty', dest='TTY', help='TTY')
        parser.add_argument('-user', dest='USER', help='USERNAME')
        parser.add_argument('-host',  dest='HOST', help='HOST')
        parser.add_argument('-ip',  dest='IP', help='IP')
        parser.add_argument('-time', dest='TIME', help='TIME')
        parser.add_argument('-start', metavar='TIME', dest='TIME_S',
                    help='Start time. e.g. 2017/1/1-08:00')
        parser.add_argument('-end', metavar='TIME', dest='TIME_E',
                    help='End time.   e.g. 2017/1/1-09:00')
    elif cmd == 'check':
        parser.add_argument('-a', action='store_true', help='Show all columns')
        parser.add_argument('-o', dest='HTML_NAME', help='HTML format output.',
                    default='utmp-lastlog-diff.html')
    elif cmd == 'add':
        parser.add_argument('-type', type=int, dest='TYPE', help='TYPE', 
                    required=True, choices=(6,7))
        parser.add_argument('-pid', type=int, dest='PID', help='PID')
        parser.add_argument('-tty', dest='TTY', help='TTY')
        parser.add_argument('-user', dest='USER', help='USERNAME')
        parser.add_argument('-time', dest='TIME', help='TIME', required=True)
        parser.add_argument('-ms', dest='MS', help='MS')
        parser.add_argument('-ip',  dest='IP', help='IP')
        parser.add_argument('--ignore-ctime', action='store_true', 
                    help='Ignore ctime. Avoid modifying system time')
    elif cmd == 'delete':
        parser.add_argument('-r', action='store_true', help='Reserve select records')
        parser.add_argument('-type', type=int, dest='TYPE', help='TYPE')
        parser.add_argument('-pid', type=int, dest='PID', help='PID')
        parser.add_argument('-tty', dest='TTY', help='TTY')
        parser.add_argument('-user', dest='USER', help='USERNAME')
        parser.add_argument('-host',  dest='HOST', help='HOST')
        parser.add_argument('-ip',  dest='IP', help='IP')
        parser.add_argument('-time', dest='TIME', help='TIME')
        parser.add_argument('-start', metavar='TIME', dest='TIME_S',
                    help='Start time. e.g. 2017/1/1-08:00')
        parser.add_argument('-end', metavar='TIME', dest='TIME_E',
                    help='End time.   e.g. 2017/1/1-09:00')
        parser.add_argument('--ignore-ctime', action='store_true', 
                    help='Ignore ctime. Avoid modifying system time')
    elif cmd == 'modify':
        lognames = ('wtmp', 'btmp')
        parser.add_argument('logname', choices=lognames, help='Log name')
        parser.add_argument('-touser', dest='TO_USER', help='TO USERNAME')
        parser.add_argument('-tohost',  dest='TO_HOST', help='TO HOST')
        parser.add_argument('-topid', type=int, dest='TO_PID', help='TO PID')
        parser.add_argument('-user', dest='USER', help='USERNAME')
        parser.add_argument('-host',  dest='HOST', help='HOST')
        parser.add_argument('-pid', type=int, dest='PID', help='PID')
        parser.add_argument('-time', dest='TIME', help='TIME')
        parser.add_argument('-start', metavar='TIME', dest='TIME_S',
                    help='Start time. e.g. 2017/1/1-08:00')
        parser.add_argument('-end', metavar='TIME', dest='TIME_E',
                    help='End time.   e.g. 2017/1/1-09:00')
        parser.add_argument('--ignore-ctime', action='store_true', 
                    help='Ignore ctime. Avoid modifying system time')
    elif cmd == 'import':
        lognames = ('wtmp', 'btmp')
        parser.add_argument('logname', choices=lognames, help='Log name')
        parser.add_argument('input_file', help='Write log to FILE.')
        parser.add_argument('--ignore-ctime', action='store_true', 
                    help='Ignore ctime. Avoid modifying system time')
    elif cmd == 'export':
        lognames = ('wtmp', 'btmp', 'utmp', 'btmp', 'lastlog')
        parser.add_argument('logname', choices=lognames, help='Log name')
        parser.add_argument('-o', dest='FILE', help='Write log to FILE.')
        parser.add_argument('--format-csv', dest='csv', action='store_true', 
                    help='CVS format ouput')
    args = parser.parse_args(sys.argv[2:])
    return cmd, args


def main():
    cmd, args = commandline()
    getattr(LLK(args), '%s_log' % cmd).__call__()


if __name__ == '__main__':
    main()

