from turtle import left
from share_func import *

#This line has a reference to a member of a key variable
def use_member(line, cv):
    if(line[:len(cv)] == cv):
        left_sign = ''
    else:
        left_sign = ' '
    if(left_sign + cv + ' -> ' in line):
        return True
    elif(left_sign + cv + ' . ' in line):
        return True
    
    return False


def sink_476(line, cv, sink_results, sink_cv, use_null_sink):
    if(('->' in cv) or (' . ' in cv)): #Key variables are themselves member variables of a structure
        if(has_cv(line, cv) and use_null_sink):
            sink_results.append(line)
            sink_cv.append(cv)
            use_null_sink = False
        elif(use_member(line, cv) and use_null_sink):
            sink_results.append(line)
            sink_cv.append(cv)
            use_null_sink = False

    if(use_member(line, cv) and use_null_sink):
        sink_results.append(line)
        sink_cv.append(cv)
        use_null_sink = False

    return use_null_sink

