import sys
import os
import datetime
from scan_candidate import *
import leveldb
import pickle
import subprocess
import re

dir_portscan = "./tssc01/db/portscan"
dir_passwordscan = "./tssc01/db/passwordscan"
dir_smtpscan = "./tssc01/db/smtpscan"

#check path
if not os.path.exists(dir_portscan):
    os.makedirs(dir_portscan)

db_port = leveldb.LevelDB(os.path.join(dir_passwordscan, "201706301200"))
all_scanPort=["ssh", "rdp"]

for k, v in db_port.RangeIter():
    v = pickle.loads(v) 
    scanHost = v.addr
    scanProtocol = v.proto
    scanAccount = v.account
    scanPassword = v.password
    
    '''
    print("HOST: "+scanHost)
    print("PROTOCOL: "+scanProtocol)
    print("ACCOUNT: "+scanAccount)
    print("PASSWORD: "+scanPassword)    
    '''

    try:
        result = subprocess.check_output("hydra -w 6s -q -t 4 -l "+scanAccount+" -p "+scanPassword+" " +scanHost+" "+scanProtocol, shell=True)
    except:
        print("cannot connet "+scanHost)
        
        # get scantime
        a  = re.search(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\s[0-9]{2}:[0-9]{2}:[0-9]{2}", result)
        scanTime = datetime.datetime.strptime(a.group(), "%Y-%m-%d %H:%M:%S")
        
        scanResult = "error"
        scanDesc = "cannot connect: "+scanHost
        passwordScanOutput = PasswordScanOutput(scanTime, scanResult, scanDesc)
        print(scanHost+":"+scanProtocol)
        print(passwordScanOutput.scantime)
        print(passwordScanOutput.result)
        print(passwordScanOutput.desc)
        print()
        continue
    
    # get scantime
    result = result.decode("utf-8")
    a  = re.search(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\s[0-9]{2}:[0-9]{2}:[0-9]{2}", result)
    scanTime = datetime.datetime.strptime(a.group(), "%Y-%m-%d %H:%M:%S")

    if result.find("successfully") != -1:   # PasswordCrack suceeds
        scanResult = "open"
        scanDesc = "account: "+scanAccount+",  password: "+scanPassword
        passwordScanOutput = PasswordScanOutput(scanTime, scanResult, scanDesc)
        print(scanHost+":"+scanProtocol)
        print(passwordScanOutput.scantime)
        print(passwordScanOutput.result)
        print(passwordScanOutput.desc)
        print()
    else:   # PasswordCrack fails
        scanResult = "close"
        scanDesc = "PasswordCrack failed"
        passwordScanOutput = PasswordScanOutput(scanTime, scanResult, scanDesc)
        print(scanHost+":"+scanProtocol)
        print(passwordScanOutput.scantime)
        print(passwordScanOutput.result)
        print(passwordScanOutput.desc)
        print()
