"""
For CWE-369 divide by 0 type for sink point matching
There are roughly two types.
1. operations on division and cv is the divisor (to the right of the operator /%)
2. Functions on division
"""
from share_func import has_only_cv


def is_divisin(line, cv):
    if ('/ ' + cv + ' ->') in line:
        return False
    elif ('/ (' + cv + ' ') in line:
        return True
    elif ('/ ' + cv + ';') in line:
        return True
    elif ('/ ' + cv + ' ') in line:
        return True
    elif ('% ' + cv + ' ->') in line:
        return False
    elif ('% ' + cv + ';') in line:
        return True
    elif ('% ' + cv + ' ') in line:
        return True
    else:
        return False


def is_divisin_func(line, cv):
    if not has_only_cv(line, cv):
        return False
    if 'static' == line.split(' ')[0].strip():
        return False
    if ('alloc' in line):
        return True
    elif ('JPC_CEILDIV' in line):
        return True
    else:
        return False


def sink_369(line, cv, sink_results, division_sink, division_func_sink, sink_cv):
    if is_divisin(line, cv) and division_sink:
        print('sink：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        division_sink = False

    if is_divisin_func(line, cv):
        print('sink：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        division_func_sink = False
    return division_sink, division_func_sink
