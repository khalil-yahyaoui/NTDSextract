from dissect.esedb import EseDB
import re , csv , os 

def find_complete_record_name(allObjectsNames, partial_record_name):
    for record_name in allObjectsNames:
        if str(partial_record_name) == ''.join(re.findall(r'\d+', record_name)) :
            return record_name

def extractFields(ntds_file,fields_=None):

    fh = open(ntds_file,"rb")
    db = EseDB(fh)
    fields_file = 'fields_' + ntds_file.split('.')[0] + '.csv'

    if os.path.isfile(fields_file):
        if fields_ is not None:
            fields = extractFieldsFromCSV(ntds_file,fields_)
        else: 
            fields = extractFieldsFromCSV(ntds_file)
    else:
        if fields_ is not None:
            fields = extractFieldsFromNTDS(db,fields_)
        else:
            fields = extractFieldsFromNTDS(db)
        saveToCSV(ntds_file,fields)
    return fields



def extractFieldsFromNTDS(db,fields_=None):

    print("[-] Field Extraction started")

    msysobjects = db.table("MSysObjects")
    datatable = db.table('datatable')
    allObjectsNames = []
    fields = {}
    attributeID = 'ATTc131102'
    lDAPDisplayName = 'ATTm131532'

    for record in msysobjects.records():
        name = record.get("Name")
        if name.startswith("ATT"):
            allObjectsNames.append(name)

    if fields_ is not None:
        for record in datatable.records():
            ldapDisplayName = record.get(lDAPDisplayName)
            if ldapDisplayName is None:
                continue
            if ldapDisplayName.lower() not in fields_:
                continue
            complete_record_name = find_complete_record_name(allObjectsNames, record.get(attributeID))
            if complete_record_name:
                fields[ldapDisplayName] = complete_record_name
        
    else:
        for record in datatable.records():
            complete_record_name = find_complete_record_name(allObjectsNames, record.get(attributeID))
            ldapDisplayName = record.get(lDAPDisplayName)
            if complete_record_name:
                fields[ldapDisplayName] = complete_record_name

    print("[+] Field Extraction done")

    return fields


def saveToCSV(ntds_file,fields):

    fields_file = 'fields_' + ntds_file.split('.')[0] + '.csv'
    with open(fields_file,'w') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow(fields.keys())
            csv_writer.writerow(fields.values())   
    print("[+] Writing in CSV Done")

def extractFieldsFromCSV(ntds_file,fields_=None):
    print("[-] Getting fields")
    fields_file = 'fields_' + ntds_file.split('.')[0] + '.csv'
    tmpfields = []
    with open(fields_file,'r') as file:
        csv_reader = csv.reader(file)
        for _ in csv_reader:
            tmpfields.append(_)
        attribute,header = tmpfields
    if fields_ is not None:
        fields = {i:j for i,j in zip(attribute,header) if i.lower() in fields_}
    else:
        fields = {i:j for i,j in zip(attribute,header)}
    print("[+] Getting Fields Completed")
    return fields

