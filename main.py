import argparse
import os,shutil
from dissect.esedb import EseDB
from dumpHashes import dumpHashes
from extractFields import extractFields
from extractNTDS import ParseNTDSFile

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("-n","--ntds_file", help="NTDS file path",required=True)
    parser.add_argument("-o","--out_dir", help="Output directory",required=True)
    parser.add_argument("-s","--system", help="System Hive file path")
    parser.add_argument("-d","--dump",action="store_true" ,help="Dump Users, Groups, Machine Accounts and their attributes")
    parser.add_argument("-hs","--dumpHashes",action="store_true" ,help="Dump Hashes")
    parser.add_argument("-f","--fields" ,help="Select comma seperated fields")

    options = parser.parse_args()

    if bool(options.system) ^ bool(options.dumpHashes):
        parser.error("You must specify System Hive file path to dump Hashes.")

    ntds_file = options.ntds_file
    systemFile = options.system
    out_dir = options.out_dir
    fields_ = options.fields.split(",")
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
    if options.fields:
        fields = extractFields(ntds_file,fields_)
    else:
        fields = extractFields(ntds_file)
    if options.dumpHashes:
        dumpHashes(datatable,fields,systemFile)
    elif options.dump:
        ParseNTDSFile(ntds_file,fields,datatable)

if __name__ == "__main__":
    main()