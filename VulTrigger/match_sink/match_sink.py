import sys
# from markupsafe import re
import re
import ast
from optparse import OptionParser
from sink_CWE119 import sink_119
from sink_CWE189 import sink_189
from sink_CWE22 import sink_22
from sink_CWE369 import sink_369
from sink_CWE415 import sink_415, sink_416, sink_415_goto
from sink_CWE617 import sink_617
from sink_CWE772 import sink_772
from sink_CWE835 import sink_835
from sink_CWE476 import sink_476
from slice_op2 import get_call_var

parser = OptionParser()
(options, args) = parser.parse_args()
if(len(args) != 1):
    print('Missing parameters! Please add cwe and path of vulnerability file.')
cwe = args[0] # Matching vulnerability types
old_file = args[1]
slice_file = args[2]
diff_file = args[3]  # CWE-772、401、415、835

list_key_words = ['if', 'while', 'for']  #
val_type = ['short', 'u64', 'int', 'long', 'char', 'float', 'double', 'struct', 'union', 'enum', 'const', 'unsigned', 'signed',
            'uint32_t', 'struct', 'guint', 'size_t', 'uint64_t', 'PSH_Point']
C_func = ['sizeof']
sp_operators = ['+', '-', '/', '*', '%', '&', '|', '=']


# Determine if it is a function definition
def is_funcdefine(line):
    result = get_funcname(line)
    if (len(result) == 1):
        funcname = result[0]
        res_list = line.split(funcname)
        # print(res_list)
        if (res_list[0] != ''):
            for sp in sp_operators:
                if(' ' + sp + ' ' in res_list[0]):
                    return False
            for con_key in list_key_words:
                if(con_key in res_list[0]):
                    return False
            return True
        else:
            return False
    else:
        return False


def is_number(s):
    if(s[:2] == '0x'):
        return True
    try:
        float(s)
        return True
    except ValueError:
        pass
 
    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
 
    return False

# Special cv handling (arrays, pointers, point operations, etc.)
# Take the array name if it's an array, or add spaces if it's a pointer
def special_cv_process(cv):
    if cv == '':
        print("===============!!!cv is blank ===============")
        sys.exit(1)
    if (cv[0] == '*'):
        # return cv[1:]
        cv = cv.split('*')[1].strip()

    if (cv[0] == '&'):
        cv = cv.split('&')[1].strip()
    if (('[' in cv) and (']' in cv)):  # The key variable is an array of subscripts containing the contents, and the subscript is taken as the key variable first.
        start = cv.rfind('[')
        end = cv.rfind(']')
        new_cv_str = cv[(start + 1):end]
        if new_cv_str == '':
            cv = cv[:start]
        # There is a problem when cutting '-', take out the minus sign and cut it separately
        elif '->' not in new_cv_str and '-' in new_cv_str:
            cv = new_cv_str.split('-')
        else:
            cv = re.split('[+|*|/|%|>>|<<|>|<|=]', new_cv_str)  # data [ plane + 4 ] [ end + 3 ]

    if ('.' in cv):  # pd.size->pd . size
        new_cv = ''
        cv_tmp = cv.split('.')
        for i in cv_tmp:
            new_cv += i + ' . '
        cv = [new_cv.strip(' . ')]
        if '->' not in cv[0]:  # ar->gpe.en
            return cv
        cv = cv[0]
    if ('->' in cv):
        new_cv = ''
        cv_tmp = cv.split('->')
        for i in cv_tmp:
            new_cv += i + ' -> '
        cv = [new_cv.strip(' -> ')]
        return cv
    if (type(cv) == type([])):
        return cv
    else:
        return [cv]


def get_min(sp1, sp2, sp3):  #
    if ((sp1 == -1) and (sp2 == -1) and (sp3 != -1)):
        return 'sp3'
    elif ((sp1 == -1) and (sp2 != -1) and (sp3 == -1)):
        return 'sp2'
    elif ((sp1 != -1) and (sp2 == -1) and (sp3 == -1)):
        return 'sp1'
    elif ((sp1 != -1) and (sp2 != -1) and (sp3 == -1)):
        if (sp1 < sp2):
            return 'sp1'
        else:
            return 'sp2'
    elif ((sp1 != -1) and (sp2 == -1) and (sp3 != -1)):
        if (sp1 < sp3):
            return 'sp1'
        else:
            return 'sp3'
    elif ((sp1 == -1) and (sp2 != -1) and (sp3 != -1)):
        if (sp2 < sp3):
            return 'sp2'
        else:
            return 'sp3'
    elif ((sp1 != -1) and (sp2 != -1) and (sp3 != -1)):
        if (sp1 <= sp2):
            if (sp1 <= sp3):
                return 'sp1'
            else:
                return 'sp3'
        else:
            if (sp2 <= sp3):
                return 'sp2'
            else:
                return 'sp3'


def left_process(cv, sign):  # Space the special variables on the left

    if sign == 'space' and len(cv.split(' ')) == 2:
        type = cv.split(' ')[0]
        if type in val_type:
            cv = cv.split(' ')[-1].strip()

    if sign == 'space' and 'struct' in cv:
        if '*' in cv:
            cv = cv.split('*')[-1]
        else:
            cv = cv.split(' ')[-1]
        return cv
    if sign == 'space' and cv[0] == '*':
        cv = cv.split('*')[1].strip()
    if sign == 'space' and '*' in cv:
        if len(cv.split('*')) == 2:
            cv = cv.split('*')[-1].strip()
    if sign == 'space' and 'guint' in cv:
        cv = cv.replace('guint ', '').strip()
    sp1 = cv.find('->')
    sp2 = cv.find('.')
    sp3 = cv.find('[')
    # print(sp1, sp2, sp3)
    flag = get_min(sp1, sp2, sp3)

    if (flag == 'sp1'):
        tmp_cv = cv[:sp1].strip().split(' ')[-1]
        if (sign == 'up'):
            return tmp_cv
        else:
            return (tmp_cv + cv[sp1:]).replace(' ', '')
    if (flag == 'sp2'):
        tmp_cv = cv[:sp2].strip().split(' ')[-1]
        if (sign == 'up'):
            return tmp_cv
        else:
            return (tmp_cv + cv[sp2:]).replace(' ', '')
    if (flag == 'sp3'):
        tmp_cv = cv[:sp3].strip().split(' ')[-1]
        if (sign == 'up'):
            return tmp_cv
        else:
            return (tmp_cv + cv[sp3:]).replace(' ', '')

        return cv.split(' ')[-1]
    else:
        return cv


def get_funcname(code):
    pattern = "((?:_|[A-Za-z])\w*(?:\s(?:\.|::|\->|)\s(?:_|[A-Za-z])\w*)*)\s?\("
    result = re.findall(pattern, code)

    i = 0
    while i < len(result):
        if result[i] in list_key_words:
            del result[i]
        else:
            i += 1

    return result


# cv is to the right of the equal sign (assigned to someone else)
def has_cv_fz_right(cv, line):
    if '>=' in line or '<=' in line or '==' in line or '!=' in line or '= ' not in line:
        return False
    if '"' in line:  # av_log ( s , AV_LOG_WARNING , "par->codec_type is type = [%d]\n" , par -> codec_type )
        tmp = line.split('"')
        if len(tmp) > 1 and '=' in tmp[1]:
            return False
    right = line.split('=')[-1]
    # print('right:', right)
    if (has_cv(cv, right)):
        return True

    return False


# Determine if the line is the line that returns the key variable
def is_return_cv(line, cv):
    line = line.strip()
    if (line[:7] != 'return '):
        return False

    if (' ' + cv + ' ') in line:
        return True
    else:
        return False


def find_sink(after_diff, cv_list, sink_results, sink_cv, epoch, vul_name, point_var):
    # For each cv to match sink points
    for cv in cv_list[epoch]:
        if cv.isdigit() or cv.isupper():  # If the key variable is a constant, skip it directly
            continue
        # If it is a converted cv, match the sink point from the converted line of the cv
        start_line = 0
        if '$$' in cv:
            start_line = int(cv.split('$$')[-1].strip())
            cv = cv.split('$$')[0].strip()
        array_sink = True
        pointer_sink = True
        risk_func_sink = True
        calculation_sink = True
        assert_sink = True
        path_sink = True
        free_sink = 0
        division_sink = True
        division_func_sink = True
        use_null_sink = True
        scatterlist_sink = True

        return_flag = False
        if ('[' in cv):
            array_name = cv[:(cv.find('['))]
            if array_name not in cv_list[epoch]:
                # cv_list[epoch].append(cv[:(cv.find('['))])
                cv_list[epoch] = append_cv(cv_list[epoch], cv[:(cv.find('['))])
        sp_cv = special_cv_process(cv)  #
        if (len(sp_cv) > 1):
            cv = sp_cv[0]
            for i in range(1, len(sp_cv)):  #
                if sp_cv[i] not in cv_list[epoch]:
                    # cv_list[epoch].append(sp_cv[i])
                    cv_list[epoch] = append_cv(cv_list[epoch], sp_cv[i])
        else:
            cv = sp_cv[0]
        if cv.isupper():  #
            continue
        if cv.isdigit() or cv.isupper():  #
            continue
        print("=======now CV is " + cv + "=========")
        sink_lines = after_diff[start_line:]
        # Find the line modified by diff and look for the sink point down from the line modified by diff
        for i, line in enumerate(sink_lines):
            chang_flag = 1  # Excluding the case where the if conditional statement is just a judgment even if the equal sign appears
            if is_return_cv(line, cv):
                return_flag = True
            # If the current line is a function definition line,
            # it does not participate in the sink point matching, but may involve sink point conversion (by parameter position conversion)
            if 'void' == line.strip():
                line = line + " "+ after_diff[i+1]
            if is_funcdefine(line):
                # The previous line of the function definition is not necessarily the function call line, first determine whether the previous line is the function call line (function name) to obtain the information of the previous line.
                # determine whether the cv in the function call statement parameters, if in the cv recorded down the location (the first few parameters)
                # function definition may appear across the line of the phenomenon
                func_define = line
                if 'location' not in line:
                    func_define = ''
                    num = 0
                    while 'location' not in sink_lines[i + num]:
                        func_define += sink_lines[i + num]
                        num += 1  # Number of lines across the function definition
                    func_define += sink_lines[i + num]
                func_name = get_funcname(func_define)[0]
                if func_name in sink_lines[i - 1]:
                    tmp = sink_lines[i - 1]
                    tmp = tmp[tmp.find(func_name):]
                    call_paras = tmp[tmp.find('(') + 1:tmp.find(')')].split(',')
                    cvv = ' ' + cv + ' '
                    if cvv in call_paras:
                        i = call_paras.index(cvv)
                        func_paras = func_define[func_define.find('(') + 1:func_define.rfind(')')].split(',')
                        change_cv = func_paras[i]

                        change_cv = left_process(change_cv, 'space')
                        if change_cv != cv and change_cv not in cv_list[epoch]:
                            if change_cv != '...':
                                # cv_list[epoch].append(change_cv)
                                cv_list[epoch] = append_cv(cv_list[epoch], change_cv)
                                print("The current CV spans the function, and the new CV after transformation is：", change_cv)
            # If it is a function call line, you need to determine whether it is a call to a vulnerable function,
            # and if it is and the key variable is used as the return value, you need to add the returned value to the key variable list
            func_name = get_funcname(line)
            if (' = ' in line) and (func_name != []) and return_flag:
                this_line_func = func_name[0]
                if this_line_func == vul_name:
                    print('This line is the call line to the vulnerable function and has a return value: ', line)
                    return_cv = line.split(' = ')[0].split(' ')[
                        -1].strip()  # int line = advance_line ( dst , line , stride , & y , h , interleave );
                    if return_cv != cv and return_cv not in cv_list[epoch]:
                        # cv_list[epoch].append(return_cv)
                        cv_list[epoch] = append_cv(cv_list[epoch], return_cv)
                        return_flag = False
                        print('The current CV is returned after the vulnerability function, and the new CV after the transformation is：', return_cv)
            if 'for ' in line:
                if '->' in line and ' -> ' not in line:
                    line = line.replace('->', ' -> ')
                if '*' in line and '* ' not in line:
                    line = line.replace('*', '* ')

            # Encapsulated for different vulnerability types
            if cwe == '189' or cwe == '190' or cwe == '191':
                array_sink, pointer_sink, risk_func_sink, calculation_sink, division_sink = sink_189(line, cv, sink_results, array_sink,
                                                                                      sink_cv, pointer_sink, risk_func_sink,
                                                                                      calculation_sink, point_var, division_sink)
            elif cwe == '119' or cwe == '125' or cwe == '787' or cwe == '120':
                array_sink, pointer_sink, risk_func_sink, scatterlist_sink = sink_119(line, cv, sink_results, array_sink, sink_cv,
                                                                    pointer_sink, risk_func_sink, scatterlist_sink, point_var)
            elif cwe == '617':
                assert_sink = sink_617(line, cv, sink_results, assert_sink, sink_cv)
            elif cwe == '22':
                path_sink = sink_22(line, cv, sink_results, path_sink, sink_cv)
            elif cwe == '415':
                free_sink = sink_415(line, cv, sink_results, free_sink, sink_cv, 'slices')
            elif cwe == '416':
                free_sink = sink_416(line, cv, sink_results, free_sink, sink_cv)
            elif cwe == '369':
                division_sink, division_func_sink = sink_369(line, cv, sink_results, division_sink, division_func_sink, sink_cv)
            elif cwe == '476':
                use_null_sink = sink_476(line, cv, sink_results, sink_cv, use_null_sink)

            # if 'if' in line and ('==' in line or '!=' in line or '+=' in line or '<=' in line or '>=' in line):
            if 'if ' in line:
                chang_flag = 0
            # If the current line involves a CV conversion, record the converted variables as a backup

            if has_cv_fz_right(cv, line) and chang_flag == 1:
                tmp_cv = cv
                if 'for (' in line:
                    tmp_lines = re.split('[(;]', line)
                    for tmp_line in tmp_lines:
                        if '<' in tmp_line or '>' in tmp_line:
                            if '&&' in tmp_line:
                                tmp_lines.append(tmp_line.split('&&')[-1])
                                tmp_line = tmp_line.split('&&')[0]
                            if '->' in tmp_line:
                                tmp_line = tmp_line.replace(' -> ', '$')
                            tmps = re.split('[<>]', tmp_line)
                            tmp_last = tmps[-1].strip()
                            if '$' in tmp_last:
                                tmp_last = tmp_last.replace('$', ' -> ')
                            if cv == tmp_last:
                                tmp_cv = tmps[0].strip()
                elif '+=' in line:
                    tmp_cv = line.split('+=')[0].strip()
                elif '|=' in line:
                    tmp_cv = line.split('|=')[0].strip()
                elif '-=' in line:
                    tmp_cv = line.split('-=')[0].strip()
                else:
                    tmp_cv = line.split('=')[0].strip()
                tmp_cv = left_process(tmp_cv, 'space')
                if ', ' in tmp_cv:  # x++, guest_ptr += cmp_bytes, server_ptr += cmp_bytes)
                    tmp_cv = tmp_cv.split(', ')[-1]
                if tmp_cv not in cv_list[epoch + 1] and tmp_cv not in cv_list[epoch]:
                    tmp_cv = tmp_cv+'$$'+str(i)
                    # cv_list[epoch + 1].append(tmp_cv)
                    cv_list[epoch + 1] = append_cv(cv_list[epoch + 1], tmp_cv)
                    print('CV：', line)
                    print('changed CV：', tmp_cv)
    # All current CVs are not matched to the sink point, add its previous level to the next CV to be matched cvList[epoch+1]
    if len(sink_results) == 0:
        for cv in cv_list[epoch]:
            sp_cv = special_cv_process(cv)
            if (len(sp_cv) > 1):
                cv = sp_cv[0]
                for i in range(1, len(sp_cv)):
                    # cv_list[epoch].append(sp_cv[i])
                    cv_list[epoch] = append_cv(cv_list[epoch], sp_cv[i])
            else:
                cv = sp_cv[0]
            new_cv = left_process(cv, 'up')
            if new_cv not in cv_list[epoch + 1] and new_cv not in cv_list[epoch]:
                print('The upper level of CV is：', new_cv)
                # cv_list[epoch + 1].append(new_cv)
                cv_list[epoch + 1] = append_cv(cv_list[epoch + 1], new_cv)
    print(epoch)
    print("If no sink point is found in the current cv list, the next cv to look for is：", cv_list[epoch + 1])


def find_first_use(after_diff, cv_list, sink_results, sink_cv, epoch):
    for cv in cv_list[epoch]:
        print("********** "+cv+" *********")
        for line in after_diff:
            if not has_cv_fz_left(cv, line) and has_cv(cv, line):
                print('The first use position is: ' + line)
                sink_results.append(line)
                sink_cv.append(cv)
                break


def match_sinks(slices):
    print('.......................sink is start.......................')
    epoch = 0  #
    sink_results = []
    cv_list = [[] for _ in range(20)]  # c
    sink_cv = []
    flag = 0  # Mark the location of the diff modification
    start = slices[0].find('[')
    end = slices[0].rfind(']')
    flag_point = False
    if '@@' in slices[0]:
        tmp = slices[0].split(' @@ ')[-2]
        cv_list[0] = ast.literal_eval(slices[0].split(' @@ ')[-2])
        cv_list[0] = list(set(cv_list[0]))  #
        loc = slices[0].split(' @@ ')[3]
        diff_tmp = slices[0].split(' @@ ')[1].split('_')
        index = 3
        vul_file = diff_tmp[3]
        while ('.c' not in vul_file):
            index += 1
            vul_file = vul_file + '_' + diff_tmp[index]  # Vulnerable file names may contain underscores
        vul_name = slices[0].split(' @@ ')[2].strip()
        if (vul_name[0] == '*'):
            vul_name = vul_name[1:]
        flag_point = True

        point_vars = slices[0].split(' @@ ')[-1].replace('{', '').replace('}', '').split(', ')
    else:
        cv_list[0] = ast.literal_eval(slices[0][start:(end + 1)])
        loc = slices[0].split(' ')[3]
        diff_tmp = slices[0].split(' ')[1].split('_')
        index = 3
        vul_file = diff_tmp[3]
        while ('.c' not in vul_file):
            index += 1
            vul_file = vul_file + '_' + diff_tmp[index]
        vul_name = slices[0].split(' ')[2].strip()
        if (vul_name[0] == '*'):
            vul_name = vul_name[1:]
    after_diff = []
    is_add = False

    for line in slices:
        if 'cross_layer' in line:
            this_loc = line[line.find('location: '):line.rfind(' cross_layer')].replace('location: ', '') #
        else:
            this_loc = line[line.find('location: '):line.rfind(' file')].replace('location: ', '')
        this_file = line.split('file: ')[-1].split('/')[-1]
        if flag == 0:
            if '(key_var lines)' in line:
                # The (key_var lines) flag indicates that the current line is the next line modified by diff
                # , because the modified line is not found in the vulnerability file in the diff-only type
                flag = 1
                is_add = True
            if this_loc == loc and this_file == vul_file:
                flag = 1
        if flag == 1:
            after_diff.append(line)

    if cwe == '772' or cwe == '401':
        sink_772(old_file, sink_results, diff_file, loc, vul_name)
        for tmp_cv in cv_list[0]:
            sink_cv_tmp = special_cv_process(tmp_cv)
            if (len(sink_cv_tmp) > 1):
                for i in range(1, len(sink_cv_tmp)):
                    if sink_cv_tmp[i] not in sink_cv:
                        sink_cv.append(sink_cv_tmp[i])

            sink_cv.append(sink_cv_tmp[0])
        print(sink_cv)
        return sink_results, sink_cv, cv_list
    
    if cwe == '835':
        idx = 1
        vul_define = slices[idx]
        while(slices[idx].strip()[-2:] != '.c'):
            idx += 1
            vul_define += slices[idx].strip('\n')
        sink_835(old_file, vul_define, sink_results, diff_file, loc, is_add)
        for tmp_cv in cv_list[0]:
            sink_cv_tmp = special_cv_process(tmp_cv)
            if (len(sink_cv_tmp) > 1):
                for i in range(1, len(sink_cv_tmp)):
                    if sink_cv_tmp[i] not in sink_cv:
                        sink_cv.append(sink_cv_tmp[i])

            sink_cv.append(sink_cv_tmp[0])
        print(sink_cv)
        # Look down in the slice for only the while loop statements that have a direct relationship to cv
        if not sink_results:
            for cv in sink_cv:
                for line in after_diff:
                    if ' '+cv+' ' in line:
                        if 'while (' in line:
                            sink_results.append(line)
                            break

        return sink_results, sink_cv, cv_list

    while len(sink_cv) == 0 and cv_list[epoch] and epoch < 5:
        if flag_point:
            find_sink(after_diff, cv_list, sink_results, sink_cv, epoch, vul_name, point_vars)
        else:
            find_sink(after_diff, cv_list, sink_results, sink_cv, epoch, vul_name, '')
        epoch += 1

    # For 416 type if free_sink point is not found, put the sink point in the first use position
    if cwe == '416' and not sink_cv:

        new_epoch = 0
        while len(sink_cv) == 0 and new_epoch < 5:
            find_first_use(after_diff, cv_list, sink_results, sink_cv, new_epoch)
            new_epoch += 1
    # For type 415, if the location of free is not found combine the diff file and old file to find the goto statement block
    if cwe == '415' and not sink_cv:

        sink_cv, sink_results = sink_415_goto(diff_file, old_file, sink_cv, sink_results, cv_list, loc)
    sink_cv = list(set(sink_cv))  # sink_cv
    return sink_results, sink_cv, cv_list


def has_cv(cv, line):
    # print(('*' + cv + ','))

    if ((' ' + cv + ',') in line):
        return True
    if ((' ' + cv + ';') in line):
        return True
    if ((' ' + cv + ')') in line):
        return True
    if ((' ' + cv + ' ,') in line):
        return True
    if ((' ' + cv + ' ;') in line):
        return True
    if ((' ' + cv + ' )') in line):
        return True
    if (('*' + cv + ';') in line):
        return True
    if ((' ' + cv + ' ') in line):
        return True
    if ((' ' + cv + '[') in line):
        return True
    if (('*' + cv + ',') in line):
        return True
    if (('*' + cv + ')') in line):
        return True
    if (cv + ' =') in line:
        return True

    return False


# cv is to the left of the equal sign (is assigned a value)

def has_cv_fz_left(cv, line):
    if (' = ' not in line):
        return False
    left = line.split(' = ')[0].strip()

    if (cv == left):
        return True
    if (line[:len(cv)] == cv):  #
        if (line[:(len(cv) + 1)] == cv + ' '):
            return True

    left_list = left.split(' ')
    if left_list[0] in val_type or (not left_list[0].islower()):

        if cv == left_list[-1]:  # int * buf
            return True

    if len(left_list)>1 and left_list[1] == '*' and cv == left_list[-1].strip():
        return True
    '''
    if('(' + cv + ' =' in line):
        return True
    if(' ' + cv + ' =' in line):
        return True
    if(' ' + cv + ' +=' in line):
        return True
    '''
    return False






def has_only_cv(line, cv):
    if (cv + ' ->') in line:  # cv = s, line : bs -> opaque
        lines = line.split(" ")
        index = lines.index('->')
        if cv == lines[index - 1]:
            return False
    if (cv + ' .') in line:
        return False
    return has_cv(cv, line)


# Determine if it is an expression
def is_expression(cv):
    if '->' in cv:
        cv = cv.replace(" -> ", "$")
    # ( PhotoshopProfile * ) user_data
    if '*' in cv:
        tmps = cv.split(" ")
        if tmps[tmps.index('*')-1].isalpha() and not tmps[tmps.index('*')-1].islower():
            return False
    if '[' in cv:
        pattern = "\[.*\]"
        index = re.findall(pattern, cv)
        for i in index:
            cv = cv.replace(i, '').strip()
    cvs = re.split('[*+/-]', cv)


    if len(cvs) > 1:
        return True
    else:
        return False


def cv_from_expression(tmp_cv):
    # For an expression, consider splitting out the variables with spaces,
    # and before splitting them out, you need to replace -> . Before splitting, you need to replace the ones that should not be split first
    if '->' in tmp_cv:
        tmp_cv = tmp_cv.replace(" -> ", "$")
    if '.' in tmp_cv:
        tmp_cv = tmp_cv.replace(' . ', '@')
    if '[' in tmp_cv and ']' in tmp_cv:
        tmp_cv = tmp_cv.replace(' [ ', '#')
        tmp_cv = tmp_cv.replace(' ]', '^')
    tmp_cvs = tmp_cv.split(' ')
    cvs = []
    for cv in tmp_cvs:
        if len(cv.strip()) > 1:
            if '0x' in cv:
                continue
            if cv in val_type or cv in C_func:
                continue
            if '@' in cv:
                cv = cv.replace('@', ' . ')
            if '$' in cv:
                cv = cv.replace('$', ' -> ')
            if '#' in cv and '^':
                # cv = cv.replace('#', ' [ ')
                # cv = cv.replace('^', ' ]')
                cv = cv.split('#')[0].strip()
            cvs.append(cv)
    return cvs

def append_cv(sink_cv, new_cv):
    if(new_cv in sink_cv):
        return sink_cv
    if(is_number(new_cv) == True):
        return sink_cv
    
    sink_cv.append(new_cv.strip())
    return sink_cv



def main():
    slices = []
    all_sinks = []

    with open(slice_file, 'r') as f:
        all_content = f.readlines()
        for line in all_content:

            if len(line) == 1:  # Removal of blank lines
                continue
            slices.append(line.strip())
            if (line.strip() == '------------------------------'):
                sinks, sink_cv, cv_list = match_sinks(slices)
                print('.......................sink is over.......................')

                slices = []
                for sk in sinks:
                    if (sk not in all_sinks):
                        all_sinks.append(sk)

    print('sink:')
    for i in all_sinks:
        print(i)
    # print(all_sinks)
    print('')



main()
