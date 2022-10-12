## -*- coding: utf-8 -*-
import os
import shutil
import sys
import json
from joern.all import JoernSteps
from optparse import OptionParser

command_joern = './joern testCode'
command_cfg = 'python get_cfg_relation.py'
command_pdg = 'python complete_PDG.py'
command_call = 'python access_db_operate.py'
command_slice = 'python extract_df2.py'
neo4j_start = './neo4j start-no-wait'
neo4j_stop = './neo4j stop'

f = open('./config.json')
path_data = json.load(f)

joern_fold = path_data["graph_db"]["testCode"]
slice_testCode = path_data["joern"]["testCode"]
step1_out_filepath = path_data['step1_output']['step1_output_tmp_txt']

#Delete the files under these two folders
def delete_file():
    os.chdir(path_data["joern"]["joern_exe"])
    if(os.path.exists('.joernIndex')):
        os.system('chmod +777 .joernIndex')
        shutil.rmtree('.joernIndex')
    print('delete .joernIndex')
    
    os.chdir(path_data["start_folder"])
    shutil.rmtree('./testCode')
    os.mkdir('testCode')
    
    #Delete the folder under cfg/pdg/dict
    cfg_path = path_data['graph_db']['cfg_db'] + '/testCode'
    pdg_path = path_data['graph_db']['pdg_db'] + '/testCode'
    dic_path = path_data['graph_db']['dict_call2cfgNodeId_funcID'] + '/testCode'
    if(os.path.exists(cfg_path)):
        shutil.rmtree(cfg_path)
    if(os.path.exists(pdg_path)):
        shutil.rmtree(pdg_path)
    if(os.path.exists(dic_path)):
        shutil.rmtree(dic_path)


#Determine if there are only plus lines in this diff file, if yes, return 0, otherwise return 1
def judge_addOrdel(hashs):
    print('judge')
    f = open(step1_out_filepath ,'r')
    text_lines = f.readlines()
    print(text_lines)
    file_list = []
    this_file = []
    line_flag = 0
    
    if text_lines == '':
        return
    if text_lines[0] == '\n':
        test_lines = text_lines[1:]
    for line in text_lines:
        if line == '==============================================================\n': #diff
            print("over")
            line_flag = 1
            file_list.append(this_file) #this_filediff
            this_file = []
        else:
            if line_flag == 1 and line == '\n':
                line_flag = 0
            else:
                this_file.append(line)
    print('file_list:')
    print(file_list)
    for _file in file_list:
        #file_hash = _file[0].split("/")[-1].split('diff')[0][:-1].split('_')[-3]
        file_hash = _file[0].split("/")[-1].split('diff')[0][:-1].split('_')[2]
        #print(file_hash)
        if(file_hash != hashs):
            continue
        flag = 0
        if len(_file) < 3: #
            print('This diff does not have any valid information.')
        else:
            for conseq in _file[2:]: #
                if conseq == '\n': #(、、)
                    print('this hunk is over.')
                else:
                    if(conseq.strip()[-6:] == 'Delete'):
                        flag = 1 #Delete,,flag1
                    if(conseq.strip()[-7:] == 'Replace'):
                        flag = 1
        
        return flag

        
#Place the new files to be parsed (dependency files + NEW/OLD files) into two folders
def move_to(software, cve, hashs):
    os.chdir(path_data['start_folder'])
    #CVE
    depen_list = []
    depen_file = './data/Dependency_Files/' + software + '/' + cve + '/' + '/depenfile_' + hashs + '.txt'
    if(not os.path.exists(depen_file)):
        print('No dependfile')
        depen_list = []
    else:
        with open(depen_file, 'r') as f:
            depen_list = [line.rstrip('') for line in f]
        print(depen_list)

    for i in os.listdir(slice_testCode):
        if(('testCode/' + i + '\n') not in depen_list):
            os.remove(slice_testCode + '/' + i)
        elif(i == 'parse_date.c'):
            os.remove(slice_testCode + '/' + i)
        else:
            print(i)
    
    vulfile_path = './data/C-Vulnerable_Files/' + software + '/' + cve
    for i in os.listdir(vulfile_path):
        if(hashs in i):
            vulfile = i
            break
    
    novulfile_path = './data/C-Non_Vulnerable_Files/' + software + '/' + cve
    for i in os.listdir(novulfile_path):
        if(hashs in i):
            novulfile = i
            break

    delfile = vulfile.split('_')[3]#Get the vulnerability file name (not .NEW/OLD) and delete from it to avoid duplication with NEW/OLD file content
    if(os.path.exists(slice_testCode + '/' + delfile)):
        os.remove(slice_testCode + '/' + delfile)

    cve_type = judge_addOrdel(hashs)
    print(cve_type)
    
    if(cve_type == 1):
        shutil.copy(vulfile_path + '/' + vulfile, slice_testCode)
    else:
        shutil.copy(novulfile_path +  '/' + novulfile, slice_testCode)

    for j in os.listdir(slice_testCode):
        shutil.copy(slice_testCode + '/' + j, path_data["start_folder"] + '/' + 'testCode')
    

def execute_slices(software, cve, hashs):
    delete_file() #joern/.joernIndex、/source2slices/testCode
    move_to(software, cve, hashs) #，joern/testCode

    #neo4j
    os.chdir(path_data["neo4j"])
    os.system(neo4j_stop)

    os.chdir(path_data["joern"]["joern_exe"])
    os.system(command_joern)
    print('joern is over')
    #neo4j
    os.chdir(path_data["neo4j"])
    os.system(neo4j_start)
    os.system('sleep 15s')

    #j = JoernSteps()
    #j.connectToDatabase()
    os.chdir(path_data["start_folder"])
    os.system(command_cfg)
    os.system(command_pdg)
    os.system(command_call)
    os.system(command_slice)

def main(software):
    data_path = './data/C-Diffs/' + software
    for cve in os.listdir(data_path):
        cve_path = data_path + '/' + cve
        for diff in os.listdir(cve_path):
            hashs = diff.split('_')[2]

            execute_slices(software, cve, hashs)

parser = OptionParser()
(options, args) = parser.parse_args()
if(len(args) != 1):
    print('Missing parameters! Please add software name.')
main(args[0])
