"""
Record some functions needed to match the vulnerability sink point type, which may be called by different sink point types

"""
import re
list_key_words = ['if', 'while', 'for']  # 

sp_operators = ['+', '-', '/', '*', '%', '&', '|', '=']

def has_only_cv(line, cv):
    if (cv + ' ->') in line:  # cv = s, line : bs -> opaque
        lines = line.split(" ")
        # index = lines.index('->')
        # if cv == lines[index - 1]:
        if cv in lines:
            return False
    if (cv + ' .') in line:
        return False
    return has_cv(cv, line)

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

def is_risk_func(line, cv):
    # print('this is a test.')
    if not has_cv(cv, line):  # ar -> gpe . en = g_malloc0 ( len / 2 ); 
        return False
    funcnames = get_funcname(line)
    if(funcnames == []):
        return False
    for func in funcnames:
        if ('memcpy' in func):  # 
            return True
        elif('memmove' in func):
            return True
        elif ('alloc' in func):
            return True
        elif ('memset' in func):
            return True
        elif 'strncpy' in func:
            return True
        elif 'strcmp' in func:
            return True
        elif('RTL_W16' in func):
            return True
        elif ('bytestream2_get_buffer' in func):
            return True
        elif ('get_bits' in func):
            return True
        elif ('put_bits' in func) or 'skb_put' in func:
            return True
        # elif ('copy' in func) and 'copy_size' not in func:
        #     return True
        elif ('recv' in func and 'recv ->' not in func):
            return True
        elif ('Write' in func or 'write' in func): #and '_write' not in line:
            return True
        elif 'read' in func or 'Read' in func:
            return True
        elif 'EXTRACT' in func:  # tcpdumpEXTRACT_32BITS
            return True
        elif 'TT_NEXT_U' in func:  # freetype2TT_NEXT_ULONG/INT(...)
            return True
        else:
            return False

def is_scatterlist_func(line, cv):
    if not has_cv(cv, line):  # ar -> gpe . en = g_malloc0 ( len / 2 ); 
        return False
    funcnames = get_funcname(line)
    if(funcnames == []):
        return False
    for func in funcnames:
        if "sg_set_buf" in func:
            return True
        elif 'usb_control_msg' in line or'usb_bulk_msg' in line:
            return True
        else:
            return False
def is_pointer(line, cv, point_var):  # ,
    if (cv in point_var):
        # 
        if (is_calculation(line, cv)):
            return True
        # print()
    sp_type = ''
    if (('* ' + cv + ' ') in line):
        sp_type = '* ' + cv + ' '
    elif (('*' + cv + ' ') in line):
        sp_type = '*' + cv + ' '
    elif (line[-len('* ' + cv):] == ('* ' + cv)):
        sp_type = '* ' + cv
    elif (line[-len('*' + cv):] == ('*' + cv)):
        sp_type = '*' + cv

    if (sp_type == ''):
        return False

    sp_res = line.split(sp_type)
    sp_var = sp_res[0].strip()
    if (sp_var != ''):
        sp_var = sp_var[-1]
    if (sp_var in sp_operators):
        return True
    else:
        return False


#Key variables are subscripts of arrays or used as arrays
# u8 odata [ 16 ]
def is_array(line, cv):
    # ptr += s -> frame -> linesize [ 0 ] 
    tmps = line[:line.find('[')].strip().split(" ")
    index = line[line.find('[') + 1:line.find(']')].strip()
    if index.isdigit() and len(tmps) == 2: #
        return False
    if (cv + ' [ 0 ]') in line:
        return False
    if cv + '[%d]' in line:  # n_entries[%d]
        return False
    if '[ 0 ]' in line:
        line = line.replace('[ 0 ]', '')
        if '[' and ']' not in line:
            return False

    # [],,dst[y+len]
    lbracket = line.find('[')
    rbracket = line.rfind(']')
    cv_loc = line.find(' ' + cv + ' ')
    if ((cv_loc > lbracket) and (cv_loc < rbracket)):
        return True
    '''
    if(('[' + cv + ']') in line):
        #print('1')
        return True
    elif(('[ ' + cv + ' ]') in line):
        #print('2')
        return True
    '''
    if ((' ' + cv + ' [') in line):  # 
        # print('3')
        return True
    if ((' ' + cv + '[') in line):
        # print('4')
        return True
    if (line[:len(cv)] == cv):  # 
        if (line[:(len(cv) + 2)] == cv + ' ['):
            return True
        if (line[:(len(cv) + 1)] == cv + '['):
            return True
    return False


#  sink point is an integer overflow type match due to integer arithmetic
def is_calculation(line, cv):
    if '(' in line and ')' in line:
        tmps = line[line.find('('):line.find(')') - 1]
        if ',' in tmps:
            tmps = tmps.split(',')
            for tmp in tmps:
                if (cv + ' *') in tmp or (cv + ' +') in tmp or ('* ' + cv) in tmp or ('+ ' + cv) in tmp:
                    return True
    if (cv + ' *') in line and '=' in line:
        return True
    if ('* ' + cv) in line and '=' in line:
        if '*' == line[0]:
            return False
        return True
    if (cv + ' +') in line or ('+ ' + cv) in line:
        return True
    if (cv + '+=') in line:
        return True
    if (cv + ' -') in line and (cv + ' ->') not in line:
        return True
    if ('- ' + cv) in line:
        return True
    if (cv + ' =') in line and '+' in line:
        return True
    return False
