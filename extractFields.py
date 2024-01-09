from dissect.esedb import EseDB
import re , csv , os 

def find_complete_record_name(allObjectsNames, partial_record_name):
    for record_name in allObjectsNames:
        if str(partial_record_name) == ''.join(re.findall(r'\d+', record_name)) :
            return record_name

def extractFields(ntds_file):

    fh = open(ntds_file,"rb")
    db = EseDB(fh)
    fields_file = 'fields_' + ntds_file.split('.')[0] + '.csv'

    if os.path.isfile(fields_file):
        fields = extractFieldsFromCSV(ntds_file)
    else:
        fields = extractFieldsFromNTDS(db)
        saveToCSV(ntds_file,fields)


    return fields
    
def extractFieldsFromNTDS(db):

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
    for record in datatable.records():
        complete_record_name = find_complete_record_name(allObjectsNames, record.get(attributeID))
        if complete_record_name:
            fields[record.get(lDAPDisplayName)] = complete_record_name

    print("[+] Field Extraction done")

    return fields


def saveToCSV(ntds_file,fields):

    fields_file = 'fields_' + ntds_file.split('.')[0] + '.csv'
    with open(fields_file,'w') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow(fields.keys())
            csv_writer.writerow(fields.values())   
    print("[+] Writing in CSV Done")

def extractFieldsFromCSV(ntds_file):
    print("[-] Getting fields")
    fields_file = 'fields_' + ntds_file.split('.')[0] + '.csv'
    tmpfields = []
    with open(fields_file,'r') as file:
        csv_reader = csv.reader(file)
        for _ in csv_reader:
            tmpfields.append(_)
        attribute,header = tmpfields
    fields = {i:j for i,j in zip(attribute,header) }    
    print("[+] Getting Fields Completed")
    return fields

