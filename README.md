# 0x00 LLK
LLK(Login Log checK&faKe) 是一个Linux登录日志伪造和检测日志伪造的工具，工作原理是通过读取和修改下面的二进制日志：
  /var/log/wtmp
  /var/log/btmp
  /var/run/utmp
  /var/log/lastlog

项目地址：[https://github.com/L-codes/LLK](https://github.com/L-codes/LLK)

# 0x01 Features
- 支持python 2.x和3.x
- 部分日志需要root的read和write权限
- list: 可格式化的打印出二进制文件的内容，方便分析
- check: 可自动基于日志之间的关联逻辑、时间和格式等检测人为伪造的日志记录
- add/delete/modify: 具备添加、删除和修改等日志操作功能
- import/export: 支持日志的格式化导入/导出功能(提高日志伪造的灵活性)

# 0x02 Parameter description
```
$ python3 oneshellcrack.py -h
```

# 0x03 Use examples

## list log
```
$ sudo ./llk.py list wtmp 

[+] "wtmp" log. (138 rows)
+------+-------+-------+----------+---------------------+-------------------+
| TYPE | PID   | TTY   | USER     | HOST                | TIME              |
+------+-------+-------+----------+---------------------+-------------------+
| 7    | 2945  | pts/1 | root     | 172.17.178.1        | 17/08/25 02:36:09 |
| 7    | 3127  | pts/0 | root     | 172.16.178.1        | 17/08/26 18:24:31 |
......
| 8    | 6922  | pts/2 |          |                     | 17/10/02 08:42:56 |
| 7    | 6942  | pts/2 | root     | 172.16.178.1        | 17/10/02 08:43:09 |
+------+-------+-------+----------+---------------------+-------------------+
```

## check log
```
$ sudo ./llk.py check
[-] [ /var/log/btmp.1 ] Log is tampered with!!
[-] [ /var/log/wtmp.1 ] Log is tampered with!!

[-] [ btmp, 1 errers ] Find format or logical problem
+------+-------+-----------+------+--------------+-------------------+
| TYPE | PID   | TTY       | USER | HOST         | TIME              |
+------+-------+-----------+------+--------------+-------------------+
| 6    | 6549  | ssh:notty | a    | 172.16.178.1 | 17/08/31 03:01:46 |*
| 6    | 16192 | ssh:notty | test | 172.16.178.1 | 17/09/12 05:08:19 |
| 6    | 16192 | ssh:notty | test | 172.16.178.1 | 17/09/12 05:08:24 |
| 6    | 16192 | ssh:notty | test | 172.16.178.1 | 17/09/12 05:08:28 |
| 7    | 28972 | tty4      | root |              | 17/09/18 07:31:14 |
+------+-------+-----------+------+--------------+-------------------+


[-] [ wtmp, 2 errers ] Find format or logical problem
+------+-------+-------+----------+--------------+-------------------+
| TYPE | PID   | TTY   | USER     | HOST         | TIME              |
+------+-------+-------+----------+--------------+-------------------+
| 7    | 2945  | pts/1 | root     | 172.17.178.1 | 17/08/25 02:36:09 |*
| 7    | 3127  | pts/0 | root     | 172.16.178.1 | 17/08/26 18:24:31 |
| 7    | 4137  | pts/2 | root     | 10.1.100.10  | 17/07/19 10:47:38 |*
......
```

## fake log
```
$ last
.....
root     pts/0        172.16.178.1     Fri Sep  8 22:40 - 22:40  (00:00)
root     pts/1        172.16.178.1     Fri Sep  8 11:42 - 11:46  (00:04)
root     pts/1        172.16.178.1     Fri Sep  8 11:16 - 11:37  (00:20)
root     pts/1        172.16.178.1     Fri Sep  8 04:43 - 04:57  (00:13)
hacker   pts/1        172.16.178.12    Thu Sep  7 21:24 - 00:54  (03:29)

$ sudo ./llk.py modify wtmp -user hacker -touser root -ip 172.16.178.1

$ last
.....
root     pts/0        172.16.178.1     Fri Sep  8 22:40 - 22:40  (00:00)
root     pts/1        172.16.178.1     Fri Sep  8 11:42 - 11:46  (00:04)
root     pts/1        172.16.178.1     Fri Sep  8 11:16 - 11:37  (00:20)
root     pts/1        172.16.178.1     Fri Sep  8 04:43 - 04:57  (00:13)
root     pts/1        172.16.178.1     Thu Sep  7 21:24 - 00:54  (03:29)
```


# 0x04 Problem
如在使用过程中发现bug或有好的建议，欢迎提交[Issues](https://github.com/L-codes/LLK/issues)和[Pull Requests](https://github.com/L-codes/LLK/pulls)
