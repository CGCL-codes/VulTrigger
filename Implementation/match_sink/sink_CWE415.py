"""
use-after-free type
Law of sink points.
Priority match free position
If it does not match, the modified position is considered to be incorrectly used, and the position where the CV was first used is matched.
"""


# ？
from share_func import has_only_cv


def is_free(line, cv):

    if not has_only_cv(line, cv):  # ar -> gpe . en = g_malloc0 ( len / 2 ); 
        return False
    # 
    if 'static' == line.split(' ')[0].strip():
        return False
    if ('free' in line):
        return True
    elif ('delete' in line):
        return True
    elif 'realloc' in line:
        return True
    elif 'unregister' in line:  # linux
        return True
    elif 'Destroy' in line:  # imagemagick
        return True
    elif 'close' in line:
        return True
    else:
        return False

def is_free_old(line, cv):
    # parameters = line[line.find('('):line.find(')')]
    if cv not in line:
        return False
    if ('free' in line):
        return True
    elif ('delete' in line):
        return True
    elif 'realloc' in line:
        return True
    elif 'unregister' in line:
        return True
    elif 'Destroy' in line:  # imagemagick
        return True
    else:
        return False

# double free type Find the location of two calls to free for the same cv
def sink_415(line, cv, sink_results, free_sink, sink_cv, sign):
    if sign == 'slices':
        if is_free(line, cv) and free_sink < 3:
            print('sink free：', line)
            sink_results.append(line)
            sink_cv.append(cv)
            free_sink += 1
    else:
        if is_free_old(line, cv) and free_sink < 3:
            print('sink free：', line)
            line = line.strip('\t')
            line = line.strip('\n')
            line = line + ' location: ' + sign
            sink_results.append(line)
            sink_cv.append(cv)
            free_sink += 1
    return free_sink


#  UAF type For a cv find the location of one call to free
def sink_416(line, cv, sink_results, free_sink, sink_cv):
    if is_free(line, cv) and free_sink < 3:
        print('sink free：', line)
        sink_results.append(line)
        sink_cv.append(cv)
        free_sink += 1
    return free_sink


def sink_415_goto(diff_file, old_file, sink_cv, sink_results, cv_list, loc):
    with open(old_file, 'r') as f:
        vul_content = f.readlines()

    with open(diff_file, 'r') as f:
        diff_content = f.readlines()
    # Find the deleted goto statement to get to the goto jump
    goto_line = ''
    goto_state = ''
    for line in diff_content:
        if line[0] == '-' and 'goto' in line:
            goto_line = line
            goto_state = line.split('goto')[-1].strip()
            goto_state = goto_state.replace(';', '')
    goto_list = []
    # Find the vulnerable function in the old file, and find the destination of the goto statement jump
    start = int(loc)
    flag = 0
    location = 0
    for i,  line in enumerate(vul_content[start:]):
        if (goto_state + ':') in line:
            print('goto')
            flag = 1
            location = i + start + 1
        if flag == 1:
            if line[0] == '\t':
                goto_list.append(line)
            elif (goto_state + ':') not in line and line[0] != '\t':
                break
    if goto_list:
        for cv in cv_list[0]:
            free_sink = 0
            for line in goto_list:
                location += 1
                sink_415(line, cv, sink_results, free_sink, sink_cv, str(location))
    return sink_cv, sink_results
