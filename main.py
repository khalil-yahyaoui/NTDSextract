import argparse
import os,shutil
from dissect.esedb import EseDB
from dumpHashes import dumpHashes
from extractFields import extractFields
from extractNTDS import ParseNTDSFile

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("-n","--ntds_file", help="NTDS file path",required=True)
    parser.add_argument("-O","--out_dir", help="Output directory",required=True)
    parser.add_argument("-s","--system", help="System Hive file path")
    parser.add_argument("-d","--dump",action="store_true" ,help="Dump Users, Groups, Machine Accounts and their attributes")
    parser.add_argument("-hs","--dumpHashes",action="store_true" ,help="Dump Hashes")
    parser.add_argument("-f","--fields" ,help="Select comma seperated fields")
    parser.add_argument("-o","--object" ,help="extract object and its attributes")

    options = parser.parse_args()

    if bool(options.system) ^ bool(options.dumpHashes):
        parser.error("You must specify System Hive file path to dump Hashes.")
    if bool(options.object) ^ bool(options.dump):
        parser.error("You must speicfy an object type to extract.")
    if options.object not in  ["all","user","group","machineaccount"]:
        parser.error("Currently, only users, groups and machine accounts are available.")

    ntds_file = options.ntds_file
    systemFile = options.system
    out_dir = options.out_dir
    objects = options.object

    fields_ = options.fields.split(",") if options.fields is not None else None
    
    fh =  open(ntds_file,"rb")
    db = EseDB(fh)
    datatable = db.table('datatable')


    if os.path.isdir(out_dir):
        if not os.path.isfile(out_dir + "/" + ntds_file):
            shutil.copyfile(ntds_file, out_dir + "/" + ntds_file)
        os.chdir(out_dir)
    else:
        os.makedirs(out_dir)
        shutil.copyfile(ntds_file, out_dir + "/" + ntds_file)
        os.chdir(out_dir)
    
    if options.dumpHashes:
        dumpHashes(datatable,systemFile)
    elif options.dump:
        if options.fields:
            fields = extractFields(ntds_file,fields_)
        else:
            fields = extractFields(ntds_file)
        ParseNTDSFile(ntds_file,fields,datatable,objects)

if __name__ == "__main__":
    main()