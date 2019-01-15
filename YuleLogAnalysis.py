# code below used for sans 2018 HHC.
import xml.etree.ElementTree as ET

tree = ET.parse('ho-ho-no.xml')
root = tree.getroot()

logofflist = []
# build a list of logoff events.
for evt in root:
    system = evt[0]
    evtid = system[1].text
    if (evtid == '4625'):
            logofflist.append(evt)

# Filter the list to find unique IPs.
iplist = []
for evt in logofflist:
    ip = evt[1][19].text
    iplist.append(ip)

# List unique IPs
set(iplist) # set(['10.158.210.210'], ['172.31.254.101']) or 2 IPs.

iplist.count('10.158.210.210') # 1
iplist.count('172.31.254.101') # 211

# potential suspect IP is 172.31.254.101.
# now, look at all 4624 events, and compile successes based on that IP.
# I got that IP just by looking at all the IPs for failures, and deducing
# this was the bad one.  I ended up being right, because 212 failures,
# with 2 bad IPs, and only 1 event had a different IP.

logonlist = []
for evt in root:
    system = evt[0]
    evtid = system[1].text
    if (evtid == '4624'):
            logonlist.append(evt)

susplogon = []    
for evt in logonlist:
    ip = evt[1][18].text
    if (ip == '172.31.254.101'):
            susplogon.append(evt)
len(susplogon)

# Iterate through the list to obtain usernames in the events
userlist = []
for evt in susplogon:
    print(evt[1][5].text)
    userlist.append(evt[1][5].text)
set(userlist)