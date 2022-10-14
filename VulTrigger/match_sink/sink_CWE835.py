from share_func import *
from sink_CWE772 import get_diff_message
import re

list_key_words = ['if', 'while', 'for']
val_type = ['short', 'int', 'long', 'char', 'float', 'double', 'struct', 'union', 'enum', 'const', 'unsigned', 'signed',
            'uint32_t', 'struct', 'void', 'static']

def get_funcname(code):
    # pattern = "((?:_|[A-Za-z])\w*(?:\s(?:\.|::|\->|)\s(?:_|[A-Za-z])\w*)*)\s\("
    pattern = "((?:_|[A-Za-z])\w*(?:\s(?:\.|::|\->|)\s(?:_|[A-Za-z])\w*)*)\s?\("
    result = re.findall(pattern, code)

    i = 0
    while i < len(result):
        if result[i] in list_key_words:
            del result[i]
        else:
            i += 1

    return result


def is_funcdefine(line):
    result = get_funcname(line)
    if (len(result) == 1):
        funcname = result[0]
        res_list = line.split(funcname)
        # print(res_list)
        if (res_list[0] != ''):
            if ('=' not in res_list[0]):
                for i in val_type:
                    if(i in res_list[0]):
                        return True
        else:
            return False
    
    return False

def is_con(line):
    if('while ' in line):
        return True
    elif('for ' in line):
        return True
    elif('do ' in line):
        return True
    elif(line == 'do'):
        return True
    elif(line == 'for'):
        return True
    elif(line == 'while'):
        return True
    
    return False

def get_sink_line(vul_content, func_define, start_line):
    func_define = func_define.split('location:')[0].replace(' ', '').strip()
    print('func_define: ', func_define)
    location = 0
    flag = False # marker has not reached the vulnerability function
    cnt = 0 # Count the number of flower brackets
    will_be_cal = []

    for line in vul_content:
        location += 1
        tmp_line = line.replace(' ', '').strip()
        if(tmp_line == func_define):
            flag = True
        
        if(flag == False):
            continue
        # print(line, location)

        if(location > start_line):
            break
        if(location == start_line):
            if(is_con(line.strip())):
                return line.strip(), location

        will_be_cal.append([line.strip(), location])
    will_be_cal.reverse()
    # print('will_be_cal: ', will_be_cal)

    sign = False
    for line in will_be_cal:
        tmp_line = line[0].replace(' ', '').strip()
        loc = line[1]    
        if(tmp_line != '' and tmp_line[-1] == '}'):
            cnt += 1
            sign = True
        if(tmp_line != '' and tmp_line[-1] == '{'):
            cnt -= 1
            sign = True

        if((sign== True) and (cnt < 0) and (is_con(line[0]))):
            print(cnt)
            # print(line, loc)
            return line[0].strip(), loc
    return '', 0


def get_goto_sink_line(vul_content, func_define, start_line):
    func_define = func_define.split('location:')[0].replace(' ', '').strip()
    print('func_define: ', func_define)
    goto_flag = ''
    goto_code = ''
    goto_loc = 0
    location = 0
    sign = False
    forward_line = []
    for line in vul_content:
        location += 1
        forward_line.append(line)

        if(sign and is_funcdefine(line)):#
            break

        if(line.replace(' ', '').strip() == func_define):
            sign = True# has gone through the definition line of the vulnerability function

        if(location < start_line):
            continue
                
        #Find if there is a goto statement after
        line_tmp = line.strip()
        if(line_tmp[:5] == 'goto '):
            goto_flag = line_tmp.split('goto ')[-1]
            if(goto_flag[-1] == ';' or goto_flag[-1] == ',' or goto_flag == '}'):
                goto_flag = goto_flag[:-1].strip()
                goto_code = line_tmp
                goto_loc = location
                break
    
    if(goto_flag == ''): # The function does not contain a goto statement
        return '', 0
    
    for line in forward_line:
        line = line.strip()
        if(line == goto_flag + ':'):
            return goto_code, goto_loc

    return '', 0 # Just a normal goto statement that does not form a loop

def get_recursion_sink_link(vul_content, func_define, start_line):
    func_define = func_define.split('location:')[0].strip()
    vulname = get_funcname(func_define)[0]
    location = 0
    sign = False

    for line in vul_content:
        line_tmp = line.replace(' ', '').strip()
        func_define_tmp = func_define.replace(' ', '').strip()
        location += 1

        if(sign and is_funcdefine(line)):
            print(line)
            break

        if(line_tmp == func_define_tmp):
            sign = True
        elif(line_tmp != '' and line_tmp in func_define_tmp and line_tmp[-1] == ','):
            sign = True

        if(location < start_line):
            continue

        res_func = get_funcname(line)
        if(len(res_func) > 0):
            for i in res_func:
                if(i == vulname):
                    return line.strip(), location
    
    return '', 0

def sink_835(old_file, func_define, sink_results, diff_file, loc, is_add):
    diff_mes = {}
    with open(old_file, 'r') as f:
        vul_content = f.readlines()
    
    with open(diff_file, 'r') as f:
        diff_content = f.readlines()
    # If the type diff file has a dead loop such as while(1), for(;;), then that line is also included in the sink point candidate set
    diff_loc = 0
    for i, line in enumerate(diff_content):
        if '-' == line[0]:
            if 'while (1) {' in line:
                diff_loc = i
                break

    if diff_loc != 0:
        index = diff_loc
        while index > 0:
            if diff_content[index][:2] == "@@":
                tmp_line = diff_content[index].split("@@")[1]
                num_line = int(tmp_line.split(',')[0].replace('-', '').strip())
                location = num_line + (diff_loc - index) - 1
                tmp_line = diff_content[diff_loc][1:].replace('\n', '').strip()
                sink_line = tmp_line + ' location: ' + str(location)
                sink_results.append(sink_line)
                break
            index = index - 1
    if(is_add == False):
        start_line = int(loc)
    else:
        num_fin = 0
        diff_mes = get_diff_message(diff_content)

        for start_line in diff_mes.keys():
            num_list = diff_mes[start_line]
            medium_tmp = num_list[0]
            add_tmp = num_list[1]
                                        
            if(int(loc) > (int(start_line) + medium_tmp + add_tmp + 1)):
                num_fin = add_tmp
            elif(int(loc) >= (int(start_line) + medium_tmp)):
                already_num = int(loc) - (int(start_line) + medium_tmp + 1)
                print(already_num, loc, start_line, medium_tmp)
                num_fin += already_num
                break
                    
        print(loc, num_fin)
        start_line = int(loc) - num_fin

    print('Will look for loop from ' + str(start_line) + 'up') # Find where the loop head is, this line is probably the loop head

    res_line, loc = get_sink_line(vul_content, func_define, start_line)
    print(type(res_line))
    print(type(loc))

    if(res_line == '' and loc == 0):# No loop statement found, consider goto point case and recursive case
        print('will try to find the goto type loop point from ' + str(start_line) + 'down')
        res_line, loc = get_goto_sink_line(vul_content, func_define, start_line)
    
    if(res_line == '' and loc == 0):
        print('Will try to find recursive type loop points from ' + str(start_line) + 'down')
        res_line, loc = get_recursion_sink_link(vul_content, func_define, start_line)
    if(res_line == '' and loc == 0):
        print('No matching sink point found')
        return

    new_line = res_line + ' location: ' + str(loc)
    print(new_line)
    sink_results.append(new_line)