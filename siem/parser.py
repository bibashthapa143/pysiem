import re

line = "Sep 28 04:27:18 metasploitable sshd[5452]: Failed password for root from 10.0.2.4 port 35643 ssh2"

pattern = r"^(\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) (\S+) (\w+)\[(\d+)\]: Failed password for (\S+) from (\S+) port (\d+)"

match = re.match(pattern, line)

if match:
    print("timestamp:", match.group(1))
    print("host:     ", match.group(2))
    print("program:  ", match.group(3))
    print("pid:      ", match.group(4))
    print("username: ", match.group(5))
    print("src_ip:   ", match.group(6))
    print("src_port: ", match.group(7))
else:
    print("No match")