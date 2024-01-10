import csv,sys
from base64 import b64decode as decode
from datetime import datetime

csv.field_size_limit(sys.maxsize)

FILETIME_FIELDS = [
    "badPasswordTime",
    "lastLogon",
    "lastLogoff",
    "lastLogonTimestamp",
    "pwdLastSet",
    "accountExpires",
    "lockoutTime",
    "priorSetTime",
    "lastSetTime",
    "msKds-CreateTime",
    "msKds-UseStartTime",
]

DATETIME_FIELDS = ["dSCorePropagationData", "whenChanged", "whenCreated"]

USER_ACCOUNT_CONTROL = {
    "SCRIPT": 0x0001,
    "ACCOUNTDISABLE": 0x0002,
    "HOMEDIR_REQUIRED": 0x0008,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "PASSWD_CANT_CHANGE": 0x0040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
    "TEMP_DUPLICATE_ACCOUNT": 0x0100,
    "NORMAL_ACCOUNT": 0x0200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "MNS_LOGON_ACCOUNT": 0x20000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "USE_DES_KEY_ONLY": 0x200000,
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000,
}


objectClassSchema = {"ldap": dict(), "cn": dict(), "resolve": dict()}

def saveToCSV(infos,type,ntds_file):
    headers = ['sAMAccountName'] + list(next(iter(infos.values())).keys())

    rows = []
    for samaccountname, attributes in infos.items():
        row = [samaccountname] + [attributes.get(header, '') for header in headers[1:]]
        rows.append(row)
        
    if type == "user":
        csv_file_path = 'users_' + ntds_file.split('.')[0] + '.csv' 
    elif type == "group" :
        csv_file_path = 'groups_' + ntds_file.split('.')[0] + '.csv' 
    else: 
        csv_file_path = 'machineccounts_' + ntds_file.split('.')[0] + '.csv'

    with open(csv_file_path, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(headers)
        csv_writer.writerows(rows)
    
    print("[+] Writing in CSV Done")

def formatTime(attribute):
    if isinstance(attribute,int):
        try:
            attribute_ = int(str(attribute).replace("'",""))
            attribute_ = int((attribute_ / 10**7 ) - 11644473600)
            attribute_ =  datetime.fromtimestamp(attribute_).__str__()
            attribute = attribute_
        except:
            attribute = int(str(attribute).replace("'",""))
    elif isinstance(attribute,list):
        try: 
            attribute_ = [int(str(i).replace("'","")) for i in attribute]
            attribute_ = [int((i / 10**7 ) - 11644473600) for i in attribute]
            attribute_ =  [datetime.fromtimestamp(i).__str__() for i in attribute ]
            attribute = attribute_
        except:
            attribute =  [datetime.fromtimestamp(i).__str__() for i in attribute ]
    return attribute


def parseRecord(record,fields):
    
    samAccountName = record.get(fields["sAMAccountName"])
    attributes = {}
    if samAccountName is not None :
        for field in fields.keys():
            try : 
                attribute = record.get(fields[field])
                if attribute is not None :
                    if field in (FILETIME_FIELDS + DATETIME_FIELDS):
                        attribute = formatTime(attribute)
                    if isinstance(attribute,list):
                        attribute = ",".join(str(i) for i in attribute)
                    if field == "userAccountControl":
                        uac = []
                        for key,val in USER_ACCOUNT_CONTROL.items():
                            if val & int(attribute):
                                uac.append(key)
                        attribute = "|".join(uac)
                    if field == "userCertificate":
                        attribute = bytes.fromhex(attribute[2:-1].replace('\\x', ''))
                        attribute = attribute.hex()
                    
                    if isinstance(attribute,str) or isinstance(attribute,int):
                        attributes[field] = attribute
                else : 
                    attributes[field] = ""
            except Exception as e :
                print(e,attribute,type(attribute))
                attributes[field] = ""
    return samAccountName,attributes


def cleanUpInfos(infos,fields):
    for field in fields.keys():
        try:
            if all(infos[user][field] == "" for user in infos.keys()):
                for user in infos.keys():
                    del infos[user][field]
        except:
            continue


def ParseNTDSFile(ntds_file,fields,datatable):    

    users = {}
    groups = {}
    machineAccounts = {}
    

    print("[+] Info Extraction Started")
    
    for record in datatable.records():
        ObjectType = record.get(fields["sAMAccountType"])    
        if ObjectType == 0x30000000:
            samaccountname , user = parseRecord(record,fields)
            users[samaccountname] = user
        elif ObjectType == 0x30000001:
            samaccountname , machineaccount = parseRecord(record,fields)
            machineAccounts[samaccountname] = machineaccount
        elif ObjectType == 0x10000000:
            samaccountname , group = parseRecord(record,fields)
            groups[samaccountname] = group
    
    print("[+] Info Extraction Finished")

    print("[+] Cleanup Started")
    
    cleanUpInfos(users,fields)
    cleanUpInfos(groups,fields)
    cleanUpInfos(machineAccounts,fields)
    
    print("[+] Cleanup Finished")

    saveToCSV(users,"user",ntds_file)
    saveToCSV(machineAccounts,"machineaccount",ntds_file)
    saveToCSV(groups,"group",ntds_file)


def readInfosFromCSV(csv_file_path):
    users = {}
    with open(csv_file_path, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            sam_account_name = row.get('samaccountname')
            attributes = {header: row.get(header, '') for header in csv_reader.fieldnames[1:]}
            users[sam_account_name] = attributes
    return users
