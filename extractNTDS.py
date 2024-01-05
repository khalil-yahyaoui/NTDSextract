from dissect.esedb import EseDB
import os,csv,sys, shutil

from extractFields import extractFields

csv.field_size_limit(sys.maxsize)

def saveToCSV(infos,type,ntds_file):
    headers = ['samaccountname'] + list(next(iter(infos.values())).keys())

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

def parseRecord(record,fields):
    samAccountName = record.get(fields["sAMAccountName"])
    attributes = {}
    if samAccountName is not None :
        for field in fields.keys():
            try : 
                attribute = record.get(fields[field])
                if attribute is not None :
                    if isinstance(attribute,list):
                        attribute = ",".join(str(i) for i in attribute)
                    if isinstance(attribute,str) or isinstance(attribute,int):
                        attributes[field] = attribute
                else : 
                    attributes[field] = ""
            except :
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
