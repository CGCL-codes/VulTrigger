from share_func import *
from sink_CWE369 import is_divisin


def is_risk_func_189(line ,cv):
    if not has_cv(cv, line):  # ar -> gpe . en = g_malloc0 ( len / 2 ); 
        return False
    if ('memcpy' in line):  # 
        return True
    elif ('alloc' in line):
        return True
    elif ('memset' in line):
        return True
    elif ('bytestream2_get_buffer' in line):
        return True
    elif ('get_bits' in line):
        return True
    elif ('put_bits' in line):
        return True
    elif ('copy' in line):
        return True
    elif ('recv' in line and 'recv ->' not in line):
        return True
    elif 'AcquireVirtualMemory' in line:
        return True
    elif 'TT_NEXT_U' in line: #freetype2TT_NEXT_ULONG/INT(...)
        return True
    elif 'FT_MEM_SET' in line: #freetype2memset
        return True
    elif 'do_div' in line: #()
        return True
    else:
        return False

def sink_189(line, cv, sink_results, array_sink, sink_cv, pointer_sink, risk_func_sink, calculation_sink, point_var, division_sink ):
    if is_array(line, cv) and array_sink:
        print('sink: ', line)
        sink_results.append(line)
        sink_cv.append(cv)
        array_sink = False
    if is_pointer(line, cv, point_var) and pointer_sink:
        print('sink: ', line)
        sink_results.append(line)
        sink_cv.append(cv)
        pointer_sink = False
    if is_risk_func_189(line, cv) and risk_func_sink:
        print('sink: ', line)
        sink_results.append(line)
        sink_cv.append(cv)
        risk_func_sink = False
    if is_calculation(line, cv) and calculation_sink:
        sink_results.append(line)
        calculation_sink = False
    if is_divisin(line, cv) and division_sink:
        sink_results.append(line)
        division_sink = False
    return array_sink, pointer_sink, risk_func_sink, calculation_sink, division_sink
