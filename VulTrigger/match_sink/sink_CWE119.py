from share_func import *


def sink_119(line, cv, sink_results, array_sink, sink_cv, pointer_sink, risk_func_sink, scatterlist_sink, point_var):
    if is_array(line, cv) and array_sink:
        print('sinkis an array access out of bounds: ', line)
        sink_results.append(line)
        sink_cv.append(cv)
        array_sink = False
    if is_pointer(line, cv,point_var) and pointer_sink:
        print('sinkis a pointer access out of bounds: ', line)
        sink_results.append(line)
        sink_cv.append(cv)
        pointer_sink = False
    if is_risk_func(line, cv) and risk_func_sink:
        print('sinkis the risk function using: ', line)
        sink_results.append(line)
        sink_cv.append(cv)
        risk_func_sink = False
    if is_scatterlist_func(line, cv) and scatterlist_sink:
        print("sink is the use of DMA-related functions: ", line)
        sink_results.append(line)
        sink_cv.append(cv)
        scatterlist_sink = False
    return array_sink, pointer_sink, risk_func_sink, scatterlist_sink