from share_func import has_cv


def is_assert(line, cv):

    if not has_cv(cv, line):  # ar -> gpe . en = g_malloc0 ( len / 2 );
        return False

    if ('assert' in line):
        return True
    elif ('BUG' in line):
        return True
    elif ('OVS_NOT_REACHED' in line):
        return True
    elif ('validate_as_request' in line):
        return True
    else:
        return False


def sink_617(line, cv, sink_results, assert_sink, sink_cv):
    if is_assert(line, cv) and assert_sink:
        print('sink is assert: ', line)
        sink_results.append(line)
        sink_cv.append(cv)
        assert_sink = False
    return assert_sink