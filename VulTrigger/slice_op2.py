## coding:utf-8
from general_op2 import isFuncCall
from Queue import Queue,LifoQueue,PriorityQueue
from general_op2 import *
import re

def rmv_str(s):
    while "\'" in s:
        indL = s.find('\'')
        if '\'' in s[indL + 1:]:
            indR = s.find('\'',indL+1)
            s = s[:indL] + '@@@@' + s[indR+1:]
        else:
            s = s[:indL] + '@@@@' + s[indL + 1:]
   
    while "\"" in s:
        indL = s.find('\"')
        if '\"' in s[indL + 1:]:
            indR = s.find('\"',indL+1)
            s = s[:indL] + '@@@@' + s[indR+1:]
        else:
            s = s[:indL] + '@@@@' + s[indL + 1:]
    return s

def process_str(s):
    s = s.replace(' -> ', '->').replace(' . ', '.').replace(' & ', '&').replace('[ ', '[').replace(' ]', ']')
    return s

def get_call_var(s, flag):
    print(s)
    s = rmv_str(s)
    s = process_str(s)
    if 'CreateMockRead(ping_frames.back()' in s:
        print(s)
    if s[1:].strip().startswith('(') and not s[1:].strip().startswith('(('): # (void) func(a,b);(void)
        indR = s[1:].strip().find(")")
        s = s[1:].strip()[indR+1 :]

    start = s.find('(')
    end = s.rfind(')')
    
    if((start != -1) and (end != -1)):
        res = s[start + 1:end] # 
    elif(start != -1):
        res = s[start + 1:]
    elif(end != -1):
        res = s[:end]
    else:
        print("error")
        return
    
    res = re.split('[,]', res) #，
    res = [i for i in res if i != ''] # 
    res_vars = []

    para_num = 1
    is_current_func = True

    for i in res:
        if i.strip() == '':
            continue
        if(i[0] == ' '):
            i = i[1:]
        if(i[0] == '\"' and i[-1] == '\"'):# 
            continue
        if(i[0] == '\'' and i[-1] == '\''):# 
            continue
        if flag == 2:
            res_vars.append(i.split(' ')[-1]) #
        else:#  
            sym_L  = i.rfind('<')
            sym_R = i.find(">")
            if sym_R!= -1 and sym_L != -1 and '->' not in i[sym_L:sym_R] and ' ' not in i[sym_L:sym_R]:
                i = i.split(">")[-1]
            i_list = re.split('&&|[||]', i)
            i_list = [k for k in i_list if k != ''] # 
            for j in i_list:
                if(j[0] == ' '): # 
                    j = j[1:]
                
                if "(" in j and ')' not in j: #，
                    ind = j.find('(')
                    j = j[ind+1:]
                    is_current_func = False #
                
                if ")" in j and '(' not in j:
                    ind = j.find(')')
                    j = j[:ind]
                    is_current_func = True #

                if '(' in j and ')' in j: #(const int) a
                    locL = j.rfind('(')
                    locR = j.find(')')
                    if locL < locR:
                        if locR != len(j) - 1:#(const int) a
                            j = j.split(')')[-1]
                        else:
                            if locR != locL + 1:
                                j = j[locL+1 : locR]
                    else:
                        j = j[locL+1:]


                index = get_location(j)
                if(index != -2):
                    j = j[:index]
                
                if('-' in j and '->' not in j):
                    j_list = re.split(' *[,;\/\+\*\-&] *', j)
                else:
                    j_list = re.split(' *[,;\/\+\*&] *', j)
                # j_list = re.split('[, ]|[ + ]|[ - ]|[ * ]|[ / ]|[; ][ & ]|[+]|[*]|[/]', j)
                j_list = [m for m in j_list if ((m != '') and (m != '-') and (m != '+') and (m != '/') and (m != '*') and (m != '&'))] # 
                for k in j_list: #, 
                    if((is_number(k) == False) and (is_define(k) == False)):
                        if '(' in k and ')' not in k: ####
                            inde = k.find("(")
                            k = k[inde+1:]
                            res_vars.append([k, para_num])
                        else:
                            res_vars.append([k, para_num])
                    else:
                        print()
            
        if(is_current_func == True):
            para_num += 1

    # res_vars2 = check_var_again(res_vars)
    # return res_vars2
    return res_vars


def get_arguments(db,node_id):
    node_id = int(node_id)
    q = Queue(maxsize=100)
    q.put(node_id)
    nodes = []
    while not q.empty():
        node_id = q.get()
        query_with_var = "g.v(%d).children()" % node_id
        children = db.runGremlinQuery(query_with_var)
        for child in children:                        
            child_type = child['type']
            node_id = child._id
            node_code = child['code']
            if child_type == 'Argument':
                nodes.append(child)
            elif child_type == 'Identifier':
                continue
            else:
                q.put(node_id)
    return nodes

def sub_slice_backwards(startnode, list_node, not_scan_list):
    if startnode['name'] in not_scan_list:
        return list_node, not_scan_list

    else:
        list_node.append(startnode)
        #not_scan_list.append(startnode['name'])
        not_scan_list.add(startnode['name'])
    predecessors = startnode.predecessors()
    startnode_loc = int(startnode['location'].split(':')[0])
    
    if predecessors != []:
        for p_node in predecessors: 
            if(p_node['location'] != None):
                p_node_loc = int(p_node['location'].split(':')[0])
            else:
                continue
            if(p_node_loc > startnode_loc):
                continue               
            list_node, not_scan_list = sub_slice_backwards(p_node, list_node, not_scan_list)

    return list_node, not_scan_list

#Slicing upwards
def program_slice_backwards(pdg, list_startNode, num):#startNode is a list
    list_all_node = []
    # not_scan_list = []
    not_scan_list = set()
    for startNode in list_startNode:
        list_node = [startNode]
        # not_scan_list.append(startNode['name'])
        not_scan_list.add(startNode['name'])
        predecessors = startNode.predecessors()
        startNode_loc = int(startNode['location'].split(':')[0])
        if predecessors != []:
            for p_node in predecessors:
                if(p_node['location'] != None):
                    p_node_loc = int(p_node['location'].split(':')[0])
                else:
                    continue
                if(p_node_loc > startNode_loc):
                    continue
                list_node, not_scan_list = sub_slice_backwards(p_node, list_node, not_scan_list)

        list_all_node += list_node
       
        #Add function define line
        if startNode['functionId'] in not_scan_list:
            continue
        for node in pdg.vs:
            if node['name'] == startNode['functionId']:
                list_all_node.append(node)
                not_scan_list.append(node['name'])
                break
        
    # print("list_all_node:", list_all_node)
    list_ordered_node = sortedNodesByLoc(list_all_node)

    final_list_node = []
    for node in list_ordered_node:
        new_node = [node, num]
        final_list_node.append(new_node)
    # return list_ordered_node
    return final_list_node


def sub_slice_forward(startnode, list_node, not_scan_list):
    if startnode['name'] in not_scan_list:
        return list_node, not_scan_list

    else:
        list_node.append(startnode)
        #not_scan_list.append(startnode['name'])
        not_scan_list.add(startnode['name'])
    successors = startnode.successors()
    startnode_loc = int(startnode['location'].split(':')[0])

    if successors != []:
        for p_node in successors:       
            if(p_node['location'] != None):
                p_node_loc = int(p_node['location'].split(':')[0])
            else:
                continue
            if(p_node_loc < startnode_loc):
                continue  
            list_node, not_scan_list = sub_slice_forward(p_node, list_node, not_scan_list)

    return list_node, not_scan_list

#Slicing downward
def program_slice_forward(pdg, list_startNode, num):#startNode is a list of parameters, only consider data dependency
    pdg = del_ctrl_edge(pdg)
            
    list_all_node = []
    # not_scan_list = []
    not_scan_list = set()
    for startNode in list_startNode:
        list_node = [startNode]
        # not_scan_list.append(startNode['name'])
        not_scan_list.add(startNode['name'])
        successors = startNode.successors()
        startNode_loc = int(startNode['location'].split(':')[0])
        
        if successors != []:
            for p_node in successors:
                if(p_node['location'] != None):
                    p_node_loc = int(p_node['location'].split(':')[0])
                else:
                    continue
                if(p_node_loc < startNode_loc):
                    continue
                list_node, not_scan_list = sub_slice_forward(p_node, list_node, not_scan_list)

        list_all_node += list_node

    list_ordered_node = sortedNodesByLoc(list_all_node)



    final_list_node = []
    for node in list_ordered_node:
        new_node = [node, num]
        final_list_node.append(new_node)
    # return list_ordered_node
    return final_list_node

def get_all_identifiers_and_ptrArrMem_return_list(db, node_id):
    node_id = int(node_id)
    identifiers = []
    query_with_var = "g.v(%d).children()" % node_id
    children = db.runGremlinQuery(query_with_var)
    for child in children:
        node_id = child._id
        node_type = child['type']
        node_code = child['code']
        if node_type == "Identifier":
            identifiers.append(node_code)               
        else:
            if node_type == "PtrMemberAccess" or node_type == "ArrayIndexing" or node_type == 'MemberAccess':
                node_code.replace(" ","")
                identifiers.append(node_code)            
            q = Queue(maxsize=100)
            q.put(node_id)
            while not q.empty():
                node_id = q.get()
                query_with_var = "g.v(%d).children()" % node_id
                children = db.runGremlinQuery(query_with_var)
                for child in children:                        
                    child_type = child['type']
                    child_id = child._id
                    child_code = child['code'].replace(' ','')
                    if child_type == 'Identifier':
                        identifiers.append(child_code)
                    else:
                        if child_type == "PtrMemberAccess" or child_type == "ArrayIndexing" or child_type == 'MemberAccess':
                            identifiers.append(child_code)
                        q.put(child_id)


    identifiers = list(set(identifiers))
    return identifiers

#(for upward slicing also need to cross function case, this version does not need)
def process_cross_func(to_scan_list, testID, slicetype, list_result_node, not_scan_func_list):
    if to_scan_list == []:
        return list_result_node, not_scan_func_list

    for node in to_scan_list:
        if node['name'] in not_scan_func_list:
            continue

        ret = isNewOrDelOp(node, testID)
        if ret:
            funcname = ret
            pdg = getFuncPDGByNameAndtestID(funcname, testID)              

            
            if pdg == False:
                not_scan_func_list.append(node['name'])
                continue

            else:
                result_list = sortedNodesByLoc(pdg.vs)

                not_scan_func_list.append(node['name'])

                index = 0
                for result_node in list_result_node:
                    if result_node['name'] == node['name']:
                        break
                    else:
                        index += 1

                list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                list_result_node, not_scan_func_list = process_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list)


        else:          
            ret = isFuncCall(node)#if funccall ,if so ,return funcnamelist
            if ret:

                for funcname in ret:
                    if funcname.find('->') != -1:
                        real_funcname = funcname.split('->')[-1].strip()
                        objectname = funcname.split('->')[0].strip()

                        funcID = node['functionId']
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        if src_pdg == False:
                            continue
                            
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname
                        pdg = getFuncPDGByNameAndtestID_noctrl(funcname, testID)


                    elif funcname.find('.') != -1:
                        real_funcname = funcname.split('.')[-1].strip()
                        objectname = funcname.split('.')[0].strip()

                        funcID = node['functionId']
                        # src_pdg = getFuncPDGByNameAndtestID_noctrl(funcID, testID)
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        if src_pdg == False:
                            continue
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)

                    else:
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)

                    if pdg == False:
                        not_scan_func_list.append(node['name'])
                        continue

                    else:
                        if slicetype == 0:
                            ret_node = []
                            for vertex in pdg.vs:
                                if vertex['type'] == 'ReturnStatement':#return
                                    ret_node.append(vertex)

                            result_list = program_slice_backwards(pdg, ret_node)#return
                            not_scan_func_list.append(node['name'])

                            index = 0
                            for result_node in list_result_node:
                                if result_node['name'] == node['name']:
                                    break
                                else:
                                    index += 1
                                
                            list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                            list_result_node, not_scan_func_list = process_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list)

                        elif slicetype == 1:
                            param_node = []
                            FuncEntryNode = False
                            for vertex in pdg.vs:
                                if vertex['type'] == 'Parameter':#
                                    param_node.append(vertex)#
                                elif vertex['type'] == 'Function':
                                    FuncEntryNode = vertex

                            if param_node != []:
                                result_list = program_slice_forward(pdg, param_node)
                            else:
                                result_list = sortedNodesByLoc(pdg.vs)

                            not_scan_func_list.append(node['name'])
                            index = 0

                            for result_node in list_result_node:
                                if result_node['name'] == node['name']:
                                    break
                                else:
                                    index += 1

                            if FuncEntryNode != False:
                                result_list.insert(0, FuncEntryNode)
                                
                            list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                            list_result_node, not_scan_func_list = process_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list)


    return list_result_node, not_scan_func_list

#This function seems to find only 3 layers up (for the case of upward slicing also need to cross the function, this version does not need)
def process_crossfuncs_back_byfirstnode(list_tuple_results_back, testID, i, not_scan_func_list):
    #is not a good way in time, list_tuple_results_back=[(results_back, itertimes)]
    while i < len(list_tuple_results_back):
        iter_time = list_tuple_results_back[i][1]
        if iter_time == 3 or iter_time == -1:#allow cross 3 funcs:
            i += 1
            continue

        else:
            list_node = list_tuple_results_back[i][0]

            if len(list_node) == 1:
                i += 1
                continue

            if list_node[1]['type'] == 'Parameter':#
                func_name = list_node[0]['name']#id
                path = os.path.join('dict_call2cfgNodeID_funcID', testID, 'dict.pkl')

                if not os.path.exists(path):
                    i += 1
                    continue

                fin = open(path, 'rb')
                _dict = pickle.load(fin)
                fin.close()
                
                if func_name not in _dict.keys():
                    list_tuple_results_back[i][1] = -1
                    i += 1
                    continue

                else:                
                    list_cfgNodeID = _dict[func_name]#
                    dict_func_pdg = getFuncPDGBynodeIDAndtestID(list_cfgNodeID, testID)#pdg
                    iter_time += 1 #+1
                    _new_list = []
                    for item in dict_func_pdg.items():
                        targetPDG = item[1]
                        startnode = []
                        for n in targetPDG.vs:
                            if n['name'] == item[0]:#is id
                                startnode = [n]
                                break
                        
                        if startnode == []:
                            continue
                        if startnode[0]['name'] in not_scan_func_list:
                            continue
                        ret_list = program_slice_backwards(targetPDG, startnode)#
                        not_scan_func_list.append(startnode[0]['name'])#()

                        ret_list = ret_list + list_node #，list_node
                        _new_list.append([ret_list, iter_time])

                    if _new_list != []:
                        del list_tuple_results_back[i] #，ret_listlist_tuple_results_back
                        list_tuple_results_back = list_tuple_results_back + _new_list
                        list_tuple_results_back, not_scan_func_list = process_crossfuncs_back_byfirstnode(list_tuple_results_back, testID, i, not_scan_func_list)
                    else:
                        list_tuple_results_back[i][1] = -1
                        i += 1
                        continue
                        

            else:
                funcname = list_node[0]['code']
                if funcname.find("::") > -1:

                    path = os.path.join('dict_call2cfgNodeID_funcID', testID, 'dict.pkl')#get funname and it call place
                    if not os.path.exists(path):
	                    i += 1
	                    continue
                    fin = open(path, 'rb')
                    _dict = pickle.load(fin)
                    fin.close()



                    func_name = list_node[0]['name']
                    # print _dict.keys()
                    if func_name not in _dict.keys():
                        list_tuple_results_back[i][1] = -1
                        i += 1
                        continue

                    else:               
                        list_cfgNodeID = _dict[func_name]
                        dict_func_pdg = getFuncPDGBynodeIDAndtestID(list_cfgNodeID, testID)
                        
                        iter_time += 1
                        _new_list = []
                        for item in dict_func_pdg.items():
                            targetPDG = item[1]
                            startnode = []
                            for n in targetPDG.vs:
                                if n['name'] == item[0]:#is id
                                    startnode = [n]
                                    break
                            if startnode == []:
                                continue 
                            if startnode[0]['name'] in not_scan_func_list:
                                continue   
                            ret_list = program_slice_backwards(targetPDG, startnode)
                            not_scan_func_list.append(startnode[0]['name'])
                            
                            
                            ret_list = ret_list + list_node
                            _new_list.append([ret_list, iter_time])

                        # print "_new_list: ",_new_list
                        if _new_list != []:
                            del list_tuple_results_back[i]
                            list_tuple_results_back = list_tuple_results_back + _new_list
                            list_tuple_results_back, not_scan_func_list = process_crossfuncs_back_byfirstnode(list_tuple_results_back, testID, i, not_scan_func_list)

                        else:
                            list_tuple_results_back[i][1] = -1
                            i += 1
                            continue

                else:
                    i += 1
                    continue
                   
    return list_tuple_results_back, not_scan_func_list


def backward_to_decl(db, startnode, variable_name):
    #tarck backward dataflow to identifierDeclaration of the cirital variable 
    identifierDecl, variable_name = select_predecessors(db,startnode, variable_name)
    if identifierDecl == []:
        return []

    return identifierDecl

def select_predecessors(db, startnode, variable_name):
    varias = []
    identifierDecl = []
    predecessors = startnode.predecessors()

    query_with_var = "g.v(%d).parents().parents().parents()" % int(startnode['name'])
    parents = db.runGremlinQuery(query_with_var)

    if len(parents) == 1 and parents[0]['type'] == 'ForStatement':
        identifs = []
        query_with_var = "g.v(%d).children().children().children()" % int(parents[0]._id)
        identifiers = db.runGremlinQuery(query_with_var)
        for ident in identifiers:
            if ident['type'] == 'Identifier':
                identifs.append(ident['code'])

        for identi in identifs:
            if variable_name == identi:
                query_with_var = "g.v(%d).children()" % int(parents[0]._id)
                chilren = db.runGremlinQuery(query_with_var)
                for pre in predecessors:
                    for child in chilren:
                        if int(pre['name']) == child._id and pre['type'] == 'Condition':
                            return [pre],variable_name

    if "*" in variable_name:
        variable_name = variable_name.split("*")[-1]

    for p_node in predecessors:
        node_type = p_node['type']
        code = p_node['code']
        node_id = int(p_node['name'])
        idents_in_pre = get_all_identifiers_and_ptrArrMem_return_list(db, node_id)
        if node_type == 'IdentifierDeclStatement' or node_type == 'Parameter':
            if variable_name.strip() in idents_in_pre:
                identifierDecl.append(p_node)
    if identifierDecl == []: #，
        class_name = ''
        array_name = ''
        if "->" in variable_name:
            class_name = variable_name.split("->")[0]
            for p_node in predecessors:
                node_type = p_node['type']
                code = p_node['code']
                if node_type == 'IdentifierDeclStatement' or node_type == 'Parameter': 
                    if class_name in code:
                        identifierDecl.append(p_node)
                        variable_name = class_name
                        break

        elif "." in variable_name:
            class_name = variable_name.split(".")[0]
            for p_node in predecessors:
                node_type = p_node['type']
                code = p_node['code']
                if node_type == 'IdentifierDeclStatement' or node_type == 'Parameter':
                    if class_name in code:
                        identifierDecl.append(p_node)
                        variable_name = class_name
                        break
        elif "[" in variable_name and "]" in variable_name:
            array_name = variable_name.split('[')[0]
            for p_node in predecessors:
                node_type = p_node['type']
                code = p_node['code']
                if node_type == 'IdentifierDeclStatement' or node_type == 'Parameter':
                    if array_name in code:
                        identifierDecl.append(p_node)
                        variable_name = array_name
                        break

        else:
            print("NO PREDESSORS???")
            return [], variable_name

    if len(identifierDecl) != 1:
        print("The number of identifierdel ERRORS!!!")
    return identifierDecl, variable_name

# is a function call with no return value, or a return value of error
def is_just_function_call(startnode):
    if(startnode['type'] != 'ExpressionStatement'):
        return False
    start_code = startnode['code'].strip()
    func = isFuncCall(startnode)
    if(func != False):
        func_before = start_code.split(func[0])[0] #
        if('=' in func_before):
            if(func_before.split(' = ')[0].strip() == 'error'):
                return True
            elif(func_before.split(' = ')[0].strip() == 'ret'):
                return True
            else:
                return False
        else:
            return True
    else:
        return False

# Get the pointer type parameter in the function call statement
def get_cv(vul_define_node, startnode):
    point_para_idx = []
    point_para = []
    idx = 1
    start_code = startnode['code'].strip()
    for para_node in vul_define_node:
        para = para_node['code']
        if('*' in para):
            point_para_idx.append(idx)
        idx += 1
    cvs = get_call_var(start_code, 1)
    print(cvs)

    for cv_message in cvs:
        cv = cv_message[0]
        cv_idx = cv_message[1]
        if(cv_idx in point_para_idx): #If a parameter is a function call, add all its arguments if the call return value is of pointer type
            point_para.append(cv)

    return point_para   


#Get the slice after the return of the vulnerable function
def process_return_func(j, vul_define_node, list_start_node, testID, layer, vulfunc, cnt, current_layer): #startnode

    if(layer <= 0):
        return []

    list_ret_slice = []
    func_id = list_start_node['functionId'] #id
    #func_name = node['code'] #
    path = os.path.join('dict_call2cfgNodeID_funcID', testID, 'dict.pkl')

    if(not os.path.exists(path)):
        print("can't find func_call in _dict.")
        return []
    fin = open(path, 'rb')
    _dict = pickle.load(fin)
    fin.close()

    if(func_id not in _dict.keys()):
        print('func_id is not in _dict.')
        return []
    else:
        cfgNodeID = _dict[func_id] #
        func_pdg = getFuncPDGBynodeIDAndtestID(cfgNodeID, testID)#pdg
        print(len(func_pdg.items()), "layer:", layer)
        #fdscgfre
        #
        for item in func_pdg.items():#
            targetPDG = item[1]
            print(item)
            startnode = []
            new_define_node = []
            for n in targetPDG.vs:
                if(n['type'] == 'Parameter'):
                    new_define_node.append(n)
                if(n['name'] == item[0]):
                    list_start_node = n #startnode
                    # new_vulfunc = isFuncCall(list_start_node)[0]
                    if(isFuncCall(list_start_node) != False):
                        new_vulfunc = isFuncCall(list_start_node)[0]
                    else:
                        new_vulfunc = ''
                    startnode = [n] #startnode
                    break
            if(startnode == []):
                return []
            if(new_define_node == []):
                print('Function parameter node not found.')
            
            new_startnode = []
            if(is_just_function_call(startnode[0])): # startnode
                cvs = get_cv(vul_define_node, startnode[0]) #Take the pointer variable in the parameter and use it as the key variable to look up.
                for cv in cvs:
                    idenDecl = backward_to_decl(j, startnode[0], cv)
                    for ide in idenDecl:
                        new_startnode.append(ide)
            # if(new_startnode != []):
            #     startnode = new_startnode
            
            #Slicing down from this statement (considering only data dependencies)
            if(new_startnode != []):
                ret_for = program_slice_forward(targetPDG, new_startnode, current_layer + 1)
            else:
                ret_for = program_slice_forward(targetPDG, startnode, current_layer + 1)

            new_ret_for = []
            if(new_startnode != []):
                can_append = False
                for ret_for_tmp in ret_for: #
                    if(ret_for_tmp[0]['name'] == startnode[0]['name']):
                        can_append = True
                    if(can_append):
                        new_ret_for.append(ret_for_tmp)

                ret_for = new_ret_for

            #list_resut_back = return_cross_func(ret_for, testID, 0, ret_for, [], cnt)
            #See if there are any cross-functions in these downward slices
            list_result_for, not_scan = return_cross_func(ret_for, testID, 1, ret_for, startnode, new_vulfunc, cnt, current_layer + 1)
            print('list_result_for:')
            print(list_result_for)
            
            #Get the slice after return, the list_ret_slice passed in here will always seem to be []
            all_result = process_return_func(j, new_define_node, list_start_node, testID, layer - 1, new_vulfunc, cnt, current_layer + 1)
            #list_ret_slice.append(list_result_for + all_result)
            print('all_result:')
            print(all_result)
            
            if(all_result == []):
                list_ret_slice.append(list_result_for)
            else:                
                for ab in all_result:
                    list_ret_slice.append(list_result_for + ab)
                       
          
    return list_ret_slice

# The role of performing downward spanning functions
# current_layer: the current layer of the spanning function for the vulnerable function
def return_cross_func(to_scan_list, testID, slicetype, list_result_node, not_scan_func_list, vulfunc, cnt, current_layer):
    if(cnt <= 0):
        return list_result_node, not_scan_func_list

    for node in to_scan_list:
        node = node[0]
        num = cnt


        ret = isNewOrDelOp(node, testID)
        if ret:
            funcname = ret
            pdg = getFuncPDGByNameAndtestID(funcname, testID)
            #cnt -= 1
            num -= 1

            if pdg == False:
                not_scan_func_list.append(node['name'])
                continue

            else:
                # result_list = sortedNodesByLoc(pdg.vs)
                result_list_tmp = sortedNodesByLoc(pdg.vs)
                for rl in result_list_tmp:
                    new_rl = [rl, current_layer + 1]
                    result_list.append(new_rl)

                not_scan_func_list.append(node['name'])

                index = 0
                for result_node in list_result_node:
                    if result_node[0]['name'] == node[0]['name']:
                        break
                    else:
                        index += 1

                list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                list_result_node, not_scan_func_list = return_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list, cnt, current_layer + 1)


        else:          
            ret = isFuncCall(node)#if funccall ,if so ,return funcnamelist
            if ret:
                
                for funcname in ret:
                    if(funcname == vulfunc):
                        continue
                    if funcname.find('->') != -1:
                        real_funcname = funcname.split('->')[-1].strip()
                        objectname = funcname.split('->')[0].strip()

                        funcID = node['functionId']
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        if src_pdg == False:
                            continue
                            
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:#
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname #,
                        pdg = getFuncPDGByNameAndtestID_noctrl(funcname, testID)

                        num -= 1


                    elif funcname.find('.') != -1:
                        real_funcname = funcname.split('.')[-1].strip()
                        objectname = funcname.split('.')[0].strip()

                        funcID = node['functionId']
                        # src_pdg = getFuncPDGByNameAndtestID_noctrl(funcID, testID)
                        src_pdg = getFuncPDGByfuncIDAndtestID(funcID, testID)
                        if src_pdg == False:
                            continue
                        classname = False
                        for src_pnode in src_pdg.vs:
                            if src_pnode['code'].find(objectname) != -1 and src_pnode['code'].find(' new ') != -1:
                                tempvalue = src_pnode['code'].split(' new ')[1].replace('*', '').strip()
                                if tempvalue.split(' ')[0] != 'const':
                                    classname = tempvalue.split(' ')[0]
                                else:
                                    classname = tempvalue.split(' ')[1]

                                break

                        if classname == False:
                            continue

                        funcname = classname + ' :: ' + real_funcname
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)
                        #cnt -= 1 #
                        num -= 1

                    else:
                        pdg = getFuncPDGByNameAndtestID(funcname, testID)#pdg
                        #cnt -= 1 #
                        num -= 1

                    if pdg == False:
                        not_scan_func_list.append(node['name'])
                        continue

                    else:
                       
                        if slicetype == 1:
                            param_node = []
                            FuncEntryNode = False
                            for vertex in pdg.vs:
                                if vertex['type'] == 'Parameter':
                                    param_node.append(vertex)
                                elif vertex['type'] == 'Function':
                                    FuncEntryNode = vertex
                                    
                            result_list = []
                            if param_node != []:
                                result_list = program_slice_forward(pdg, param_node, current_layer + 1) # ，current_ayer+1
                            else:
                                result_list_tmp = sortedNodesByLoc(pdg.vs) # 
                                for rl in result_list_tmp:
                                    new_rl = [rl, current_layer + 1]
                                    result_list.append(new_rl)


                            not_scan_func_list.append(node['name'])
                            index = 0

                            for result_node in list_result_node:
                                if result_node[0]['name'] == node['name']:
                                    break
                                else:
                                    index += 1

                            if FuncEntryNode != False:
                                result_list.insert(0, [FuncEntryNode, current_layer + 1])
                                
                            list_result_node = list_result_node[:index+1] + result_list + list_result_node[index+1:]

                            list_result_node, not_scan_func_list = return_cross_func(result_list, testID, slicetype, list_result_node, not_scan_func_list, vulfunc, num, current_layer + 1)#


    return list_result_node, not_scan_func_list