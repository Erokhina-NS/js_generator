import os
import random
import sys
import shutil
import pytz
from datetime import datetime
from copy import deepcopy
from subprocess import Popen, PIPE, TimeoutExpired

import torch

from fuzz.resolve import hoisting, resolve_id, update_builtins
from fuzz.resolve_bug import ResolveBug
from utils import data2tensor, get_node_type, hash_frag, is_single_node, is_node_list, kill_proc, load_pickle, trim_seed_name, write
from utils.harness import Harness
from utils.node import PROP_DICT, TERM_TYPE, get_define_node, get_load_node
from utils.printer import CodePrinter
from utils.parse import SingleParser
from preprocess.fragmentize import fragmentize
from utils import print_msg

HELP_FILE = '/home/notebooks/erokhina/code_generator/data/help/fuzzing'
MAIN_PATH = '/home/notebooks/erokhina/code_generator/'
PATH_TO = MAIN_PATH+'My_way/'
JS_DIR = 'js_list_res'
COV_FIRST = {'lines': {'percent': '49.7', 'count': '1921', 'all': '3868'}, 
             'functions': {'percent': '56.9', 'count': '550', 'all': '967'}} 

class Fuzzer:
    def __init__(self, mode):
        self._eng_path = PATH_TO+'ChakraCore/out/Release/ch'
        self._model_path = MAIN_PATH+'data/models/epoch-70.model'
        self._seed_dir = MAIN_PATH+"js-test-suite/testsuite/"
        self._data_dir = MAIN_PATH+"data/"
        self._bug_dir = PATH_TO+'bugs/'
        self._top_k = 16#64

        self._harness = Harness(MAIN_PATH+"js-test-suite/testsuite")
    
        if os.path.exists(self._bug_dir):
            shutil.rmtree(self._bug_dir)
        os.makedirs(self._bug_dir)

        seed, data, train = load_data(self._data_dir)
        (self._seed_dict,
         self._frag_list,
         self._new_seed_dict) = seed
        (self._new_frag_list,
         self._new_frag_dict,
         self._oov_pool,
         self._type_dict) = data
        (_, _, self._type_list, _) = train
        
        try:
            update_builtins(self._eng_path)
        except Exception as err:
            print('update_builtins_ERR=' + str(err))
        ####################################
        self._mode = mode
        self._stack_list = list()
        self._stack_list_next = list()
        self._js_list = []
    ############################################################################           
    def frag2idx(self, frag):
        node_type = get_node_type(frag)
        hash_val = hash_frag(frag)
        if hash_val in self._new_frag_dict:
            return self._new_frag_dict[hash_val]
        else:
            return self._new_frag_dict[node_type]
    def idx2frag(self, frag_idx):
        frag = self._frag_list[frag_idx]
        frag = deepcopy(frag)
        return frag
    def info2tensor(self, parent_idx, frag_type):
        parent_idx = [parent_idx]
        parent_idx = data2tensor(parent_idx)
        frag_type = [self._type_dict[frag_type]]
        frag_type = data2tensor(frag_type,
                                tensor_type="Float")
        return parent_idx, frag_type

    def postprocess(self, root, harness_list):
        # Insert Load
        try:
            body = [get_define_node(self._seed_dir)]
            for jspath in harness_list:
                load_node = get_load_node(jspath)
                if load_node not in body:
                    try:
                        body.append(load_node)
                    except Exception as err:
                        #print('body.append(load_node)_ERR=' + str(err))
                        pass
            try:
                body.append(root)
                root = {
                    'type': 'Program',
                    'body': body,
                    'sourceType': 'script'
                }
                return root
            except Exception as err:
                #print('body.append(root)_ERR=' + str(err))
                return None
        except Exception as err:
            #print('get_define_node_ERR=' + str(err))
            return None 
    def resolve_errors(self, root, harness_list):
        # ID Resolve
        try:
            symbols = hoisting(root, ([], []), True)
            resolve_id(root, None, symbols, True,
                       cand=[], hlist=harness_list)
        except ResolveBug as error:
            msg = 'Resolve Failed: {}'.format(error)
            #print(msg)
            pass
    
    def build_ast(self, node, stack, frag):
        node_type = get_node_type(node)
        for key in PROP_DICT[node_type]:
            if key not in node: continue
            child = node[key]
            # If it has a single child
            if is_single_node(child):
                if not is_pruned(child):
                    frag = self.build_ast(child, stack, frag)
                # Expand the frag
                elif frag:
                    self.push(stack, frag)
                    node[key] = frag
                    return None
            # If it has multiple children
            elif is_node_list(child):
                for idx, _child in enumerate(child):
                    if _child == None:
                        continue
                    elif not is_pruned(_child):
                        frag = self.build_ast(child[idx], stack, frag)
                    # Expand the frag
                    elif frag:
                        self.push(stack, frag)
                        child[idx] = frag
                        return None
        return frag
    def build_seed_tree(self, seed_name, frag_seq):
        max_idx = len(frag_seq) - 1
        idx = random.randint(2, max_idx)
        # Find subtree to be pruned
        pre_seq = frag_seq[:idx]
        pruned_seq = frag_seq[idx:]
        root, post_seq = self.build_subtree(pruned_seq)
        # Build the seed tree
        frags = pre_seq + [-1] + post_seq
        stack = []
        root, _ = self.build_subtree(frags, stack)
        parent_idx, frag_type = stack.pop(0)
        # Get OoV version of frags
        pre_seq, _ = self._new_seed_dict[seed_name]
        pre_seq = pre_seq[:idx]
        return root, pre_seq, parent_idx, frag_type
    def build_subtree(self, frag_seq, stack=None):
        frag_idx = frag_seq.pop(0)
        root = self.idx2frag(frag_idx)
        self.traverse(root, frag_seq, stack)
        return root, frag_seq
    def traverse(self, node, frag_seq, stack):
        node_type = get_node_type(node)
        if node_type not in TERM_TYPE:
            parent_idx = self.frag2idx(node)
        else:
            return
        for key in PROP_DICT[node_type]:
            if key not in node: continue
            child = node[key]
            # If it has a single child
            if is_single_node(child):
                if is_pruned(child):
                    frag_idx = frag_seq.pop(0)
                    if frag_idx == -1:
                        if stack != None:
                            frag_info = (parent_idx,
                                         get_node_type(child))
                            stack.append(frag_info)
                        continue
                    frag = self.idx2frag(frag_idx)
                    node[key] = frag
                self.traverse(node[key], frag_seq, stack)
            # If it has multiple children
            elif is_node_list(child):
                for idx, _child in enumerate(child):
                    if _child == None:
                        continue
                    elif is_pruned(_child):
                        frag_idx = frag_seq.pop(0)
                        if frag_idx == -1:
                            if stack != None:
                                frag_info = (parent_idx,
                                             get_node_type(_child))
                                stack.append(frag_info)
                            continue
                        frag = self.idx2frag(frag_idx)
                        child[idx] = frag
                    self.traverse(child[idx], frag_seq, stack)
    def push(self, stack, node):
        parent_idx = self.frag2idx(node)
        node_type = get_node_type(node)
        for key in reversed(PROP_DICT[node_type]):
            if key not in node: continue
            child = node[key]

            if (type(child) == dict and
                    is_pruned(child)):
                info = (parent_idx, get_node_type(child))
                stack.append(info)
            elif type(child) == list:
                for _child in reversed(child):
                    if _child != None and is_pruned(_child):
                        info = (parent_idx, get_node_type(_child))
                        stack.append(info)
    
    def select_seed(self):
        seed_list = list(self._seed_dict.keys())
        frag_len = -1
        while frag_len < 3:
            seed_name = random.choice(seed_list)
            frag_seq, _ = self._seed_dict[seed_name]
            frag_len = len(frag_seq)
        return (seed_name, frag_seq)
    def prepare_seed(self, param, model):
        # Prepare AST
        (seed_name, frag_seq) = param
        (root,
         pre_seq,
         parent_idx,
         frag_type) = self.build_seed_tree(seed_name, frag_seq)
        
        # Prepare input for the model
        frag = [pre_seq[-1]]
        pre_seq = pre_seq[:-1]
        model_input = data2tensor(pre_seq)
        try:
            hidden = model.run(model_input)
            model_input = (frag, hidden, parent_idx, frag_type)
            seed_name = trim_seed_name(seed_name)
            return seed_name, root, model_input
        except Exception as err:
            print('model.run_ERR=' + str(err))
            return None
    def append_frag(self, cand_list, ins_cnt, root, stack, hidden_new):
        # Try all fragments in top k
        variants = []
        variants_print = []
        variants_end = []
        variants_end_print = []
        for cand_idx in cand_list:
            cand_frag = self._new_frag_list[cand_idx]
            parent_idx, frag_type = self.expand_ast(cand_frag,
                                                        stack, root)
            frag = [cand_idx]

            if parent_idx == None:
                variants_end.append((ins_cnt, stack, root, frag, parent_idx, frag_type, hidden_new))
                variants_end_print.append(('stack='+str(stack), 'frag='+str(frag), 'parent_idx='+str(parent_idx), 'frag_type='+str(frag_type)))
                stack = []
            else:
                variants.append((ins_cnt, stack, root, frag, parent_idx, frag_type, hidden_new))
                variants_print.append(('stack='+str(stack), 'frag='+str(frag), 'parent_idx='+str(parent_idx), 'frag_type='+str(frag_type)))
                stack = []
        if variants != [] or variants_end != []:  
            return True, variants, variants_end
        else:
            return False, [], []
    def expand_ast(self, frag, stack, root):
        # Out-of-vocabulary
        if type(frag) == str:
            frag_type = frag
            frag = random.choice(self._oov_pool[frag_type])
        frag = deepcopy(frag)
        try:
            self.build_ast(root, stack, frag)
        except Exception as err:
            print('build_ast_ERR=' + str(err))
        if len(stack) == 0:
            return None, None
        else:
            parent_idx, frag_type = stack.pop()
            return parent_idx, frag_type
    
    def get_cand(self, model, model_input): 
        frag, hidden, parent_idx, frag_type = model_input
        try:
            frag = data2tensor(frag)
            valid_type = frag_type                
            try:
                parent_idx, frag_type = self.info2tensor(parent_idx,
                                                         frag_type)
                try:
                    outputs, hidden_new = model.run(frag, hidden,
                                                parent_idx, frag_type)
                    try:
                        _, cand_tensor = torch.topk(outputs[0][0],
                                                    self._top_k)
                        cand_list = cand_tensor.data.tolist()
                        cand_list_cor = self.type_check(cand_list, valid_type)
                        return cand_list_cor, hidden_new
                    except Exception as err:
                            print('torch.topk_ERR=' + str(err))
                            return None
                except Exception as err:
                    print('model.run_ERR=' + str(err))
                    return None
            except Exception as err:
                print('info2tensor_ERR=' + str(err))
                return None
        except Exception as err:
            print('data2tensor_ERR=' + str(err))
            return None
    def type_check(self, cand_list, valid_type):
        for cand_idx in cand_list: 
            cand_frag = self._new_frag_list[cand_idx]  
            if type(cand_frag) == dict:
                cand_type = get_node_type(cand_frag)
            else:
                cand_type = cand_frag
            if cand_type != valid_type:
                cand_list.remove(cand_idx)                  
        return cand_list
    def cov_check(self, root, printer, ins_cnt, js_path=None, flag=False):
        if js_path == None:
            js_path = printer.ast2code(root)
            #############################                            
        if js_path == None or js_path == '':
            return None
        else:
            try:
                d, out = get_cov('ONE', js_path, self._mode)
                if d == {} and out != None and COV_FIRST != {}:  
                    try:
                        st = (out).split('Overall coverage rate:\\n')[1].split('\\n')[:2]
                    except Exception:
                        return None    
                    dct = {}
                    for i in st:
                        v1 = i.split(':')[1].split('%')[0]
                        v2 = i.split(':')[1].split('%')[1].split('of')[0].replace('(','')
                        v3 = i.split(':')[1].split('%')[1].split('of')[1].split(' ')[1]
                        d2 = {'percent': v1, 'count': v2, 'all':v3}
                        dct[i.split(':')[0].replace('.', '').replace(' ', '')] = d2
                    d = dct.copy()
                if flag: 
                    if float(d['lines']['percent']) > 0 or float(d['functions']['percent']) > 0:
                        print('NOT_EDITED_FILE_COV='+str(d))
                        write(PATH_TO+JS_DIR+'/all_js_cov_list.txt', 'NOT_EDITED_FILE_COV___js_path = '+js_path+' COV = '+ str(d),'a')
                        return None
                else:
                    if float(COV_FIRST['lines']['percent']) < float(d['lines']['percent']) or float(COV_FIRST['functions']['percent']) < float(d['functions']['percent']):   
                            shutil.copy(js_path, PATH_TO+JS_DIR)
                            print('INCREASED___COV_NEW='+str(d))
                            js_path = PATH_TO+JS_DIR +'/'+ str(js_path.split('/')[::-1][0])
                            print('js='+str(js_path))
                            write(PATH_TO+JS_DIR+'/js_list.txt', 'js_path = ' + js_path +' ins_cnt=' + str(ins_cnt) + ' NEW_COV = '+ str(d),'a')
                            set_new_cov(d, self._mode)
                            return js_path
                    elif float(COV_FIRST['lines']['percent']) > float(d['lines']['percent']) or float(COV_FIRST['functions']['percent']) > float(d['functions']['percent']): 
                        print('DECREASED___COV_NEW='+str(d))
                        return None
                    else:
                        # print('error')
                        return None
            except Exception as err:
                print('get_cov_ERR=' + str(err))
                return None
    ############################################################################
    def add_new_to_base(self, js_path):
        parser = SingleParser(PATH_TO)
        ast_path = parser.parse(js_path)                                         
        (file_name, _frag_seq, _frag_info_seq, _node_types) = fragmentize(ast_path)
        hash_frag_list = set()
        frag_seq, frag_info_seq = [], []
        for node_type in _node_types:
            if node_type not in self._type_list:
                self._type_dict[node_type] = len(self._type_list)
                self._type_list += [node_type]
        for frag in _frag_seq:
            hash_val = hash_frag(frag)
            # New fragment
            if hash_val not in hash_frag_list:
                hash_frag_list.add(hash_val)
                frag_idx = len(self._frag_list)
                self._new_frag_dict[hash_val] = frag_idx
                self._frag_list += [frag]
            # Existing fragment, but different hash
            elif hash_val not in self._new_frag_dict:
                frag_idx = self._frag_list.index(frag)
            # Existing fragment
            else:
                frag_idx = self._new_frag_dict[hash_val]
            frag_seq += [frag_idx]
        for next_parent_idx, frag_type in _frag_info_seq:
            next_parent_frag = frag_seq[next_parent_idx]
            type_idx = self._type_dict[frag_type]
            frag_info = (next_parent_frag, type_idx)
            frag_info_seq += [frag_info]
        file_name_new = file_name.decode('utf-8')
        self._seed_dict[file_name_new] = (frag_seq, frag_info_seq)
        self._new_seed_dict[file_name_new] = (frag_seq, frag_info_seq)
        self._js_list.append(js_path)

    def fuzz(self):
        try:
            model = load_model(self._model_path)
            try:
                printer = CodePrinter(self._bug_dir,PATH_TO)
                count = 0
                while True:
                    count+=1
                    time_start = datetime.now(pytz.timezone('Europe/Moscow'))
                    print_msg('START '+str(count)+' at TIME='+str(time_start.time()),'INFO',HELP_FILE, True)
                    param = self.select_seed()
                    js_path = self.gen_code(0, param, printer, model)
                    time_start2 = datetime.now(pytz.timezone('Europe/Moscow'))
                    time_del = time_start2 - time_start
                    print_msg('STOP '+str(count)+' at TIME='+str(time_start2.time())+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)
                    if js_path == None: 
                        continue
                    else:
                        sys.exit(1)
            except Exception as err:
                print('self.printer_ERR=' + str(err))
                run(self._mode)
        except Exception as err:
            print('self.model_ERR=' + str(err))
            sys.exit(1)

    def gen_code(self, ins_cnt, param, printer, model):
        ################################
        #         if first step
        (seed_name, root, model_input) = self.prepare_seed(param, model)
        print('seed_name='+seed_name)
        start_root = root
        frag, hidden, parent_idx, frag_type = model_input
        if parent_idx != None:
            ins_cnt += 1
            cand_list, hidden_new = self.get_cand(model, model_input)
            stack = []
            found, variants, _ = self.append_frag(cand_list,ins_cnt, start_root, stack, hidden_new)
            if not found:
                msg = 'Failed to select valid frag at %d' % ins_cnt
                print(msg)
                return None
            elif variants != []: 
                for val in range(len(variants)):
                    ins_cnt, stack, root, frag, parent_idx, frag_type, hidden = variants[val]
                    d = dict()
                    d['ins_cnt']=ins_cnt
                    d['val']=[val]
                    d['root']=root
                    d['hidden']=hidden
                    d['stack']=stack
                    d['frag_seq'] = [(frag,parent_idx,frag_type)]
                    self._stack_list.append(d)  
                variants = []
        else:
            return None
        ############################################
        if self._stack_list:
           
            # if next step
            count_step = 2
            while self._stack_list != [] and count_step != 4: 
                print('count_step='+str(count_step))
                count_step += 1
                for dct in self._stack_list:
                    ins_cnt=dct['ins_cnt']
                    ins_cnt+=1
                    prev_val=dct['val']                    
                    prev_root=dct['root']
                    prev_hidden =dct['hidden']
                    prev_stack=dct['stack']
                    prev_frag_seq = dct['frag_seq']
                    (prev_frag,prev_parent_idx,prev_frag_type) = prev_frag_seq[-1]
                    prev_model_input = prev_frag, prev_hidden, prev_parent_idx, prev_frag_type
                    cand_list, new_hidden  = self.get_cand(model, prev_model_input)
                    found, variants, variants_end = self.append_frag(cand_list, ins_cnt, prev_root, prev_stack, new_hidden)                
                    if not found:
                        msg = 'Failed to select valid frag at %d' % ins_cnt
                        pass  
                    elif variants != []:
                        for val in range(len(variants)):
                            ins_cnt, stack, root, frag, parent_idx, frag_type, hidden = variants[val]                                
                            d = dict()
                            d['ins_cnt']=ins_cnt
                            new_val = list()
                            for v in prev_val:
                                new_val.append(v)
                            new_val.append(val)
                            d['val']= new_val
                            d['root']= root
                            d['hidden']=hidden
                            d['stack']= stack
                            frag_seq_list = list()
                            for v in prev_frag_seq:
                                frag_seq_list.append(v)
                            frag_seq_list.append((frag, parent_idx, frag_type))
                            d['frag_seq'] = frag_seq_list                            
                            self._stack_list_next.append(d)                                
                        variants = []                        
                    elif variants_end != []:
                        for var in variants_end:                                    
                            ins_cnt, stack, root, frag, parent_idx, frag_type, hidden = var 
                            try:
                                harness_list = self._harness.get_list(seed_name)
                                self.resolve_errors(root, harness_list)
                                try:
                                    root = self.postprocess(root, harness_list)
                                    try:
                                        time_start3 = datetime.now(pytz.timezone('Europe/Moscow'))
                                        print_msg('START cov_check at TIME='+str(time_start3.time()),'INFO',HELP_FILE, True)
                                        js_path = self.cov_check(root, printer, ins_cnt)
                                        time_start4 = datetime.now(pytz.timezone('Europe/Moscow'))
                                        time_del2 = time_start4 - time_start3
                                        print_msg('STOP cov_check at TIME='+str(time_start4.time())+',  DELTA= '+str(time_del2),'INFO',HELP_FILE, True)
                                    except Exception as err:
                                        print('err'+str(err))
                                        sys.exit(1)
                                    if js_path != None:
                                        print('JS_PATH=' + str(js_path))
                                        write(PATH_TO+JS_DIR+'/js_list.txt', 'seed_name = '+seed_name,'a')
                                    continue
                                except Exception as err:
                                    continue
                            except Exception as err:
                                continue
                        variants_end = []
                    else:
                        pass
                self._stack_list.clear()
                self._stack_list = self._stack_list_next.copy()
                self._stack_list_next.clear()
                time_start5 = datetime.now(pytz.timezone('Europe/Moscow'))
                print_msg('START cov_check at TIME='+str(time_start5.time()),'INFO',HELP_FILE, True)
                for d in self._stack_list:
                    print("(ins_cnt={0}, val={1}, stack={2}, frag_seq={3})".format(d['ins_cnt'], d['val'], d['stack'], d['frag_seq']))    
                time_start6 = datetime.now(pytz.timezone('Europe/Moscow'))
                time_del3 = time_start6 - time_start5
                print_msg('STOP cov_check at TIME='+str(time_start6.time())+',  DELTA= '+str(time_del3),'INFO',HELP_FILE, True)
                


def get_cov(mode, js_path, mode2):
    eng_path = PATH_TO+'ChakraCore/out/Release/'    
    if mode == 'ALL':
        cmd = [eng_path+'ch'] + [] + [js_path]
    elif mode == 'ONE':
        if mode2 == 'COV_ZERO':
            sh_path = MAIN_PATH+'My_Cov_zero.sh'
        elif mode2 == 'COV_FIRST':
            sh_path = MAIN_PATH+'My_Cov_zero.sh'
        js_name = js_path.split('/')[::-1][0].split('.js')[0]
        cmd = [sh_path] + [eng_path] + [js_path] + [js_name] + [PATH_TO]
        # print(cmd)
    with Popen(cmd, stdout=PIPE, stderr=PIPE) as proc:
        try:
            stdout, stderr = proc.communicate(input=None, timeout=20)
            html_path = PATH_TO+'COV_NEXT/output/index.html'   
            try:
                with open(html_path, "r") as f:
                    content = f.read()
                    content = content.split('<img src="glass.png" width=3 height=3 alt="">')[1].split('</tr>')
                    dct = {}    
                    for i in range(2,4):
                        v = []
                        for s in content[i].split('</td>'):
                            if 'headerCovTableEntry' in s:
                                v.append(s.split('>')[1].replace(' ', ''))
                        d2 = {'percent': v[2].replace('%', ''), 'count': v[0], 'all':v[1]}
                        dct[i] = d2
                    dct['lines'] = dct.pop(2)
                    dct['functions'] = dct.pop(3)
                    return dct,stdout
            except Exception as err:
                return {},stdout
        except TimeoutExpired:
            print('TimeoutExpired')
            proc.kill()
            return None,None
def set_new_cov(cov_dict, mode):
    global COV_FIRST
    COV_FIRST = cov_dict
    cmd = [MAIN_PATH+'Set_Cov.sh'] + [PATH_TO+mode+'/'] + [PATH_TO]
    with Popen(cmd, stdout=PIPE, stderr=PIPE) as proc:
        try:
            stdout, stderr = proc.communicate(input=None, timeout=20)
            return 0
        except TimeoutExpired:
            print('TimeoutExpired')
            proc.kill()
            return 0

def is_pruned(node):
    keys = node.keys()
    return (len(keys) == 1 and
            'type' in keys and
            get_node_type(node) not in TERM_TYPE)
def load_data(data_dir):
    data_path = os.path.join(data_dir,
                             'data.p')
    seed_data_path = os.path.join(data_dir,
                                  'seed.p')
    train_data_path = os.path.join(data_dir,
                                  'train_data.p')

    seed = load_pickle(seed_data_path)
    data = load_pickle(data_path)
    train = load_pickle(train_data_path)
    return seed, data, train
def load_model(model_path):
    try:
        model = torch.load(model_path, map_location=torch.device('cuda'))
        try:
            model.cuda()
            try:
                model.eval()
                return model
            except Exception as err:
                print('model.eval_ERR=' + str(err))
                sys.exit(1)
        except Exception as err:
            print('model.cuda_ERR=' + str(err))
            sys.exit(1)
    except Exception as err:
        print('torch.load_ERR=' + str(err))
        sys.exit(1)

def run(mode):
    try:
        fuzzer = Fuzzer(mode)
        try:
            fuzzer.fuzz()
        except Exception as err:
            print('fuzzer.fuzz_ERR=' + str(err))
            sys.exit(1)
    except Exception as err:
        print('Fuzzer_INIT_ERR=' + str(err))
        sys.exit(1)

def main():   
    
    if not torch.cuda.is_available():
        print('ERROR: code_generator only supports CUDA-enabled machines')
        sys.exit(1)

    mode = 'COV_ZERO'
    mode2 = 'zero'
    global COV_FIRST
    if mode == 'COV_ZERO':
        if mode2 == 'zero':            
            COV_FIRST['lines']['percent'] = 0
            COV_FIRST['functions']['percent'] = 0
            try:
                shutil.rmtree(PATH_TO+'COV_ZERO/')
            except Exception:
                pass
        else:
            # COV_FIRST['lines']['percent'] = '32.3'
            # COV_FIRST['functions']['percent'] = '27.5'
            pass
    print(COV_FIRST)
    
    if mode2 == 'zero' or mode == 'COV_FIRST':
        if os.path.exists(PATH_TO+JS_DIR):
            shutil.rmtree(PATH_TO+JS_DIR)
        os.makedirs(PATH_TO+JS_DIR)

    # Increase max recursion depth limit
    sys.setrecursionlimit(10000)
    run(mode)

if __name__ == '__main__':
    main()
