import os, sys, shutil, torch, random, re
from datetime import datetime
from subprocess import Popen, PIPE, TimeoutExpired
from copy import deepcopy

from fuzz.resolve import hoisting, resolve_id, update_builtins
from fuzz.resolve_bug import ResolveBug
from utils import data2tensor, get_node_type, hash_frag, is_single_node, is_node_list, kill_proc, load_pickle, trim_seed_name, write
from utils.harness import Harness
from utils.node import PROP_DICT, TERM_TYPE, get_define_node, get_load_node
from utils.printer import CodePrinter
from utils.config import Config

COVERAGE = {}

MAIN_PATH = '/home/jovyan/'
def copy_cov(first_path):
    #копирование gcda в движок
    with open(first_path+'_gcda_files.txt') as file:
        files = file.read().split('\n')
    for file_path in files:
        name = os.path.basename(file_path)  # Извлекаем имя файла
        dst = os.path.dirname(file_path)  # Извлекаем путь до файла
        if name != '':
            try:
                shutil.copy(first_path+name, dst)
            except IOError as e:
                print(f"Ошибка при копировании файла {first_path+name}: {e}")
            except:
                print(f"Неизвестная ошибка")
        else:
            print(f"Неизвестная ошибка")
    return 0

class Fuzzer:
    def __init__(self, conf):
        self._src_path = conf.src_path
        self._seed_dir = conf.seed_dir
        self._harness = Harness(conf.seed_dir)
        self._max_ins = 100
        self._num_gpu = 1
        self._timeout = 20
        self._top_k = 64
        self._opt = []
        self._bug_dir = conf.bug_dir
        if os.path.exists(self._bug_dir):
            shutil.rmtree(self._bug_dir)
        os.makedirs(self._bug_dir)
        
        self._eng_exec = conf.eng_exec
        self._eng_path = conf.eng_path
        self._eng_cov = conf.eng_cov 
        self._data_dir = conf.data_dir
        self._cov_res = conf.cov_res
        if os.path.exists(self._cov_res):
            shutil.rmtree(self._cov_res)  
        os.mkdir(self._cov_res)
        self._model_path = self._data_dir+'/models/epoch-70.model'
        self._mode = conf.mode
        global COVERAGE
        self._cov = conf.cov
        value = globals()[str(self._cov)]
        COVERAGE = value.copy()
        if self._mode == 'ZERO':
            COVERAGE['lines']['percent'] = 0
            COVERAGE['lines']['count'] = 0
            COVERAGE['functions']['percent'] = 0
            COVERAGE['functions']['count'] = 0
            cmd = f'lcov --directory {self._eng_cov} --zerocounters'
            try:
                proc = Popen(cmd, stdout=PIPE, stderr=PIPE) 
                stdout, stderr = proc.communicate()
                print(stdout)
            except Exception as err:
                print('zerocounters_ERR='+str(err))
                sys.exit()
            next = MAIN_PATH+'js_generator/'+str(self._cov).split('_')[0]+'_NEXT'
            if os.path.exists(next):
                shutil.rmtree(next)
            os.mkdir(next)
        elif mode == 'FIRST':
            copy_cov(main_path+str(self._cov))
            #pass
                
        seed, data = load_data(self._data_dir)
        (self._seed_dict,
         self._frag_list,
         self._new_seed_dict) = seed
        (self._new_frag_list,
         self._new_frag_dict,
         self._oov_pool,
         self._type_dict) = data
        try:
            update_builtins(self._eng_exec)
        except Exception as err:
            print('update_builtins_ERR=' + str(err))
        
        print(f"Start settings:\n Engine: {self._eng_exec}\n Mode: {self._mode}\n Start coverage: {COVERAGE}\n##################################################################################\n")

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
                return None
        except Exception as err:
            return None
    def resolve_errors(self, root, harness_list):
        # ID Resolve
        try:
            symbols = hoisting(root, ([], []), True)
            resolve_id(root, None, symbols, True,
                       cand=[], hlist=harness_list)
        except ResolveBug as error:
            msg = 'Resolve Failed: {}'.format(error)
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
        return seed_name, frag_seq
    def prepare_seed(self, model):
        # Prepare AST
        seed_name, frag_seq = self.select_seed()
        (root,
         pre_seq,
         parent_idx,
         frag_type) = self.build_seed_tree(seed_name, frag_seq)

        # Prepare input for the model
        frag = [pre_seq[-1]]
        pre_seq = pre_seq[:-1]
        model_input_batch = data2tensor(pre_seq)
        try:
            hidden = model.run(model_input_batch)
            model_input = (frag, hidden, parent_idx, frag_type)
            seed_name = trim_seed_name(seed_name)
            return seed_name, root, model_input
        except Exception as err:
            print('model.run_ERR=' + str(err))
            return None
    def append_frag(self, cand_list, root, stack):
        # Try all fragments in top k
            cand_idx = random.choice(cand_list)
            cand_frag = self._new_frag_list[cand_idx]            
            try:
                parent_idx, frag_type = self.expand_ast(cand_frag,
                                                        stack, root)
            except Exception as err:
                print('self.expand_ast_ERR=' + str(err))
            frag = [cand_idx]
            return True, frag, parent_idx, frag_type
           
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
                    outputs, hidden = model.run(frag, hidden,
                                                parent_idx, frag_type)
                    try:
                        _, cand_tensor = torch.topk(outputs[0][0],
                                                    self._top_k)
                        cand_list = cand_tensor.data.tolist()
                        cand_list_cor = self.type_check(cand_list, valid_type)
                        return cand_list_cor
                    except Exception as err:
                            return None
                except Exception as err:
                    return None
            except Exception as err:
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
    def cov_check(self, root, printer, js_path=None, flag=False):
        if js_path == None:
            js_path = printer.ast2code(root)
        if js_path != None and js_path != '':
            global COVERAGE
            try:
                cov_res = get_cov(js_path, self._mode, self._eng_path)
                if cov_res != None and cov_res != {}: 
                    if float(COVERAGE['lines']['percent']) < float(cov_res['lines']['percent']) or float(COVERAGE['functions']['percent']) < float(cov_res['functions']['percent']):   
                        shutil.copy(js_path, self._cov_res)
                        print(f'INCREASED___COVERAGE={cov_res} by js={js_path}')
                        write(self._cov_res+'js_list.txt', f'INCREASED___COVERAGE={cov_res} by js={js_path}','a')
                        COVERAGE = cov_res.copy()
                        return js_path
                    elif float(COVERAGE['lines']['percent']) == float(cov_res['lines']['percent']) and float(COVERAGE['functions']['percent']) == float(cov_res['functions']['percent']):
                        print('COVERAGE IS EQUAL..')
                    elif float(COVERAGE['lines']['percent']) > float(cov_res['lines']['percent']) or float(COVERAGE['functions']['percent']) > float(cov_res['functions']['percent']): 
                        print(f'DECREASED___COVERAGE={cov_res} by js={js_path}')
                        write(self._cov_res+'js_list.txt', f'DECREASED___COVERAGE={cov_res} by js={js_path}','a')
                    else:
                        print('Coverage error')
            except Exception as err:
                print('get_cov_ERR=' + str(err))
        return None
    ############################################################################        
    def fuzz(self):
        try:
            model = load_model(self._model_path)
            try:
                printer = CodePrinter(self._bug_dir,self._src_path)
                while True:
                    try:
                        js_path = self.gen_code(printer, model)
                        if js_path == None: continue
                    except Exception as err:
                        print('self.gen_code_ERR=' + str(err))
                        self.fuzz()
            except Exception as err:
                print('self.printer_ERR=' + str(err))
                sys.exit(1)
        except Exception as err:
            print('self.model_ERR=' + str(err))
            sys.exit(1)
        
    
    def gen_code(self, printer, model):
        (seed_name, root, model_input) = self.prepare_seed(model)
        print(f'seed_name={seed_name} at Time={datetime.now().strftime("%H:%M:%S")}')
        stack = [] 
        ins_cnt = 0
        frag, hidden, parent_idx, frag_type = model_input
        while parent_idx != None:
            if ins_cnt >= self._max_ins:
                return None
            else:
                ins_cnt += 1
            cand_list = self.get_cand(model, model_input)   
            if cand_list == None or len(cand_list) == 0:
                return None
            (found, frag, parent_idx, frag_type) = self.append_frag(cand_list,
                                                                    root,
                                                                    stack)
             if not found:
                msg = 'Failed to select valid frag at %d' % ins_cnt
                print(msg)
                return None
        try:
            harness_list = self._harness.get_list(seed_name)
            self.resolve_errors(root, harness_list)
            try:
                root = self.postprocess(root, harness_list)
                js_path = self.cov_check(root, printer)
                if js_path != None:
                    js_path = os.path.abspath(js_path)
                    return js_path
            except Exception as err:
                print('self.postprocess_ERR=' + str(err))
                return None
        except Exception as err:
            print('harness_list_ERR=' + str(err))
            return None
        
def get_cov(js_path, mode, eng_path):
    sh_path = MAIN_PATH+'js_generator/My_Cov.sh'
    cmd = [sh_path] + [eng_path] + [js_path]
    try:
        proc = Popen(cmd, stdout=PIPE, stderr=PIPE) 
        stdout, stderr = proc.communicate()
        dct = {}
        if stderr:
            if 'Summary coverage rate:' in stderr.decode():
                err = stderr.decode().split('Summary coverage rate:')[1]
                num = re.findall(r'\d+\.\d+|\d+', err)
                dct['lines'] = {"percent": float(num[0]),"count": int(num[1]),"all": int(num[2])}
                dct['functions'] = {"percent": float(num[3]),"count": int(num[4]),"all": int(num[5])}
                return dct
        if stdout:
            if 'Summary coverage rate:' in stdout.decode():
                out = stdout.decode().split('Summary coverage rate:')[1]
                num = re.findall(r'\d+\.\d+|\d+', out)
                dct['lines'] = {"percent": float(num[0]),"count": int(num[1]),"all": int(num[2])}
                dct['functions'] = {"percent": float(num[3]),"count": int(num[4]),"all": int(num[5])}
                return dct
        return None

    except Exception as err:
        print('Popen_ERR=' + str(err)+'\n')

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

    seed = load_pickle(seed_data_path)
    data = load_pickle(data_path)
    return seed, data

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

def main():   
    if not torch.cuda.is_available():
        print('ERROR: code_generator only supports CUDA-enabled machines')
        sys.exit(1)
    # Increase max recursion depth limit
    sys.setrecursionlimit(10000)
    
    conf = Config(MAIN_PATH+'js_generator/conf.json',MAIN_PATH)
    try:
        fuzzer = Fuzzer(conf)
        try:
            fuzzer.fuzz()
        except Exception as err:
            print('fuzzer.fuzz_ERR=' + str(err))
            sys.exit(1)
    except Exception as err:
        print('Fuzzer_INIT_ERR=' + str(err))
        sys.exit(1)
    
if __name__ == '__main__':
    main()
