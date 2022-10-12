## coding:utf-8
from calendar import c
from hashlib import new
import os
import shutil
import json
from sys import path
from optparse import OptionParser

test_path = '/home/SySeVR/Implementation/source2slice/pre_data/test'
f = open('./config.json')   
path_data = json.load(f)
diff_path = path_data['all_test_code']['all_diff_path']
new_path = path_data['all_test_code']['all_new_path']
old_path = path_data['all_test_code']['all_old_path']
start_fold = path_data['start_folder']


def del_and_mkdir(cve):  # cve: new data
    os.chdir(diff_path)
    os.system('rm -r CVE*')
    os.system('mkdir ' + cve)

    os.chdir(start_fold)
    os.chdir(new_path)
    os.system('rm -r CVE*')
    os.system('mkdir ' + cve)

    os.chdir(start_fold)
    os.chdir(old_path)
    os.system('rm -r CVE*')
    os.system('mkdir ' + cve)
    
def main(software):
    for cve in os.listdir(test_path):
        src_cve_path = test_path + '/' + cve
        dst_diff_path = diff_path + cve
        dst_vul_path = old_path + cve
        dst_nvul_path = new_path + cve
        print('start del and mkdir..........')
        del_and_mkdir(cve)

        print('start copy diff and vulfile..........')
        os.chdir(start_fold)
        print(src_cve_path)
        for f in os.listdir(src_cve_path):  # copy
            print(f, f[-5:])
            if(f[-5:] == '.diff'):  # .diff
                shutil.copy(src_cve_path + '/' + f, dst_diff_path)
                print(dst_diff_path)
                print('copy diff!')
            if(f[-5:] == 'NEW.c' or f[-5:] == 'NEW.cpp'):
                shutil.copy(src_cve_path + '/' + f, dst_nvul_path)
                print(dst_nvul_path)
                print('copy new')
            if(f[-5:] == 'OLD.c' or f[-5:] == 'OLD.cpp'):
                shutil.copy(src_cve_path + '/' + f, dst_vul_path)
                print(dst_vul_path)
                print('copy old')
        print('start slice..........')
        os.chdir(start_fold)
        print('===================get_depend===================')
        os.system('python get_depen.py ' + software)
        print('===================prepare_work===================')
        os.system('python prepare_work.py ' + software)
 
parser = OptionParser()
(options, args) = parser.parse_args()
if(len(args) != 1):
    print('Missing parameters! Please add software name.')
main(args[0])
