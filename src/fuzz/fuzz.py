import os
import random
import sys
import threading
from copy import deepcopy
from subprocess import Popen
from subprocess import PIPE

import torch
from torch.multiprocessing import Pool
from torch.multiprocessing import set_start_method

from fuzz.resolve import hoisting
from fuzz.resolve import resolve_id
from fuzz.resolve import update_builtins
from fuzz.resolve_bug import ResolveBug
from utils import data2tensor
from utils import get_node_type
from utils import hash_frag
from utils import init_worker
from utils import is_single_node
from utils import is_node_list
from utils import kill_proc
from utils import load_pickle
from utils import pool_map
from utils import trim_seed_name
from utils import write
from utils.harness import Harness
from utils import print_msg
from utils.node import PROP_DICT
from utils.node import TERM_TYPE
from utils.node import get_define_node
from utils.node import get_load_node
from utils.printer import CodePrinter

HELP_FILE = ''


class Fuzzer:
    def __init__(self, proc_idx, conf, mode=''):
        print_msg('self.init(' + str(proc_idx) + ')', 'INFO', HELP_FILE)
        self._eng_path = conf.eng_path
        self._max_ins = conf.max_ins
        self._num_gpu = conf.num_gpu
        self._model_path = conf.model_path
        self._opt = conf.opt
        self._seed_dir = conf.seed_dir
        self._bug_dir = os.path.join(conf.bug_dir,
                                     'proc.%d' % proc_idx)
        self._timeout = conf.timeout
        self._top_k = conf.top_k

        self._harness = Harness(conf.seed_dir)
        self._help_dir = conf.help_dir
        if not os.path.exists(self._bug_dir):
            os.makedirs(self._bug_dir)
        log_path = os.path.join(self._bug_dir,
                                'logs.csv')
        self._crash_log = open(log_path, 'ab', 0)

        seed, data = load_data(conf, proc_idx)
        (self._seed_dict,
         self._frag_list,
         self._new_seed_dict) = seed
        (self._new_frag_list,
         self._new_frag_dict,
         self._oov_pool,
         self._type_dict) = data
        if mode != 'single_fuzz':
            try:
                self.assign_gpu(proc_idx)
            except Exception as err:
                print_msg('self.assign_gpu_ERR=' + str(err), 'ERROR', HELP_FILE)
        try:
            update_builtins(conf.eng_path)
        except Exception as err:
            print_msg('update_builtins_ERR=' + str(err), 'ERROR', HELP_FILE)

    def append_frag(self, cand_list, valid_type, root, stack, proc_idx):
        print_msg('self.append_frag(' + str(proc_idx) + ')', 'INFO', HELP_FILE)
        # Try all fragments in top k
        print_msg('cand_list=' + str(cand_list), 'MY', HELP_FILE)
        print_msg('len(cand_list)=' + str(len(cand_list)), 'MY', HELP_FILE)
        while len(cand_list) > 0:
            cand_idx = random.choice(cand_list)
            print_msg('cand_idx=' + str(cand_idx), 'MY', HELP_FILE)
            cand_frag = self._new_frag_list[cand_idx]
            print_msg('cand_frag=' + str(cand_frag), 'MY', HELP_FILE)

            if type(cand_frag) == dict:
                cand_type = get_node_type(cand_frag)
            else:
                cand_type = cand_frag

            if cand_type == valid_type:
                try:
                    parent_idx, frag_type = self.expand_ast(cand_frag,
                                                            stack, root)
                except Exception as err:
                    print_msg('self.expand_ast_ERR=' + str(err), 'ERROR', HELP_FILE)
                frag = [cand_idx]
                return True, frag, parent_idx, frag_type
            else:
                cand_list.remove(cand_idx)
        return False, None, None, None

    def assign_gpu(self, proc_idx):
        print_msg('self.assign_gpu', 'INFO', HELP_FILE)
        gpu_idx = proc_idx % self._num_gpu
        try:
            os.environ['CUDA_VISIBLE_DEVICES'] = '%d' % gpu_idx
        except Exception as err:
            print_msg('self.assign_gpu_ERR=' + str(err), 'ERROR', HELP_FILE)

    def build_ast(self, node, stack, frag):
        print_msg('self.build_ast', 'INFO', HELP_FILE)
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
        print_msg('self.build_seed_tree', 'INFO', HELP_FILE)
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
        print_msg('self.build_subtree', 'INFO', HELP_FILE)
        frag_idx = frag_seq.pop(0)
        root = self.idx2frag(frag_idx)
        self.traverse(root, frag_seq, stack)
        return root, frag_seq

    def exec_eng(self, js_path):
        print_msg('self.exec_eng', 'INFO', HELP_FILE)
        cmd = [self._eng_path] + self._opt + [js_path]
        print_msg('cmd=' + str(cmd), 'MY', HELP_FILE)
        try:
            proc = Popen(cmd, cwd=self._seed_dir, stdout=PIPE, stderr=PIPE)  
            timer = threading.Timer(self._timeout, kill_proc, [proc])
            timer.start()
            stdout, stderr = proc.communicate()
            timer.cancel()
            if stderr:
                print_msg('stderr=' + str(stderr), 'MY', HELP_FILE)
            if stdout:
                print_msg('stdout=' + str(stdout), 'MY', HELP_FILE)
            print_msg('returncode=' + str(proc.returncode), 'MY', HELP_FILE)
            if proc.returncode in [-4, -11]:
                log = [self._eng_path] + self._opt
                log += [js_path, str(proc.returncode)]
                log = str.encode(','.join(log) + '\n')
                print_msg('log=' + str(log), 'MY', HELP_FILE, True)
                self._crash_log.write(log)
                msg = 'Found a bug (%s)' % js_path
                print_msg(msg, 'WARN', HELP_FILE, True)
                sys.exit(1)
            else:
                os.remove(js_path)
        except Exception as err:
            print_msg('Popen_ERR=' + str(err), 'ERROR', HELP_FILE)

    def expand_ast(self, frag, stack, root):
        print_msg('self.expand_ast', 'INFO', HELP_FILE)
        # Out-of-vocabulary
        if type(frag) == str:
            frag_type = frag
            frag = random.choice(self._oov_pool[frag_type])
            print_msg('len(self._oov_pool[frag_type])=' + str(len(self._oov_pool[frag_type])), 'MY', HELP_FILE)
            print_msg('random.choice=' + str(frag), 'MY', HELP_FILE)
        frag = deepcopy(frag)
        try:
            self.build_ast(root, stack, frag)
        except Exception as err:
            print_msg('build_ast_ERR=' + str(err), 'ERROR', HELP_FILE)
        if len(stack) == 0:
            return None, None
        else:
            parent_idx, frag_type = stack.pop()
            return parent_idx, frag_type

    def frag2idx(self, frag):
        print_msg('self.frag2idx', 'INFO', HELP_FILE)
        node_type = get_node_type(frag)
        hash_val = hash_frag(frag)
        if hash_val in self._new_frag_dict:
            return self._new_frag_dict[hash_val]
        else:
            return self._new_frag_dict[node_type]

    def fuzz(self, proc_idx):
        print_msg('self.fuzz(' + str(proc_idx) + ')', 'INFO', HELP_FILE)
        try:
            model = load_model(self._model_path, proc_idx)
            try:
                printer = CodePrinter(self._bug_dir,HELP_FILE)
                while True:
                    js_path = self.gen_code(printer, model, proc_idx)
                    if js_path == None: continue
                    js_path = os.path.abspath(js_path)
                    print_msg('js_path=' + str(js_path), 'MY', HELP_FILE, True)
                    try:
                        self.exec_eng(js_path)
                        print_msg('exec_eng=OK', 'MY', HELP_FILE)
                    except Exception as err:
                        print_msg('self.exec_eng_ERR=' + str(err), 'ERROR', HELP_FILE, True)
            except Exception as err:
                print_msg('self.printer_ERR=' + str(err), 'ERROR', HELP_FILE)
        except Exception as err:
            print_msg('self.model_ERR=' + str(err), 'ERROR', HELP_FILE)

    def gen_code(self, printer, model, proc_idx):
        print_msg('self.gen_code(' + str(proc_idx) + ')', 'INFO', HELP_FILE)
        stack = []
        ins_cnt = 0
        (seed_name,
         root, model_input) = self.prepare_seed(model)
        frag, hidden, parent_idx, frag_type = model_input
        print_msg('parent_idx='+ str(parent_idx), 'MY', HELP_FILE)
        while parent_idx != None:
            if ins_cnt >= self._max_ins:
                return None
            else:
                ins_cnt += 1
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
                            print_msg('cand_list=' + str(cand_list), 'MY',
                                      HELP_FILE)

                            try:
                                (found, frag, parent_idx, frag_type) = self.append_frag(cand_list,
                                                                                        valid_type,
                                                                                        root,
                                                                                        stack,
                                                                                        proc_idx)

                                if not found:
                                    msg = 'Failed to select valid frag at %d' % ins_cnt
                                    print_msg(msg, 'WARN', HELP_FILE)
                                    return None
                                else:
                                    try:
                                        harness_list = self._harness.get_list(seed_name)
                                        print_msg('harness_list=' + str(harness_list), 'MY',
                                                  HELP_FILE)
                                        self.resolve_errors(root, harness_list)
                                        try:
                                            root = self.postprocess(root, harness_list)
                                            try:
                                                js_path = printer.ast2code(root)
                                                print_msg('js_path=' + str(js_path), 'MY', HELP_FILE)
                                                return js_path
                                            except Exception as err:
                                                print_msg('self.ast2code_ERR=' + str(err), 'ERROR', HELP_FILE)
                                                return None
                                        except Exception as err:
                                            print_msg('self.postprocess_ERR=' + str(err), 'ERROR', HELP_FILE)
                                            return None

                                    except Exception as err:
                                        print_msg('harness_list_ERR=' + str(err), 'ERROR', HELP_FILE)
                                        return None

                            except Exception as err:
                                print_msg('self.append_frag_ERR=' + str(err), 'ERROR', HELP_FILE)
                                return None

                        except Exception as err:
                            print_msg('torch.topk_ERR=' + str(err), 'ERROR', HELP_FILE)
                            return None
                    except Exception as err:
                        print_msg('model.run_ERR=' + str(err), 'ERROR', HELP_FILE)
                        return None
                except Exception as err:
                    print_msg('info2tensor_ERR=' + str(err), 'ERROR', HELP_FILE)
                    return None
            except Exception as err:
                print_msg('data2tensor_ERR=' + str(err), 'ERROR', HELP_FILE)
                return None

    def idx2frag(self, frag_idx):
        print_msg('self.idx2frag', 'INFO', HELP_FILE)
        frag = self._frag_list[frag_idx]
        frag = deepcopy(frag)
        return frag

    def info2tensor(self, parent_idx, frag_type):
        print_msg('self.info2tensor', 'INFO', HELP_FILE)
        parent_idx = [parent_idx]
        parent_idx = data2tensor(parent_idx)
        frag_type = [self._type_dict[frag_type]]
        frag_type = data2tensor(frag_type,
                                tensor_type="Float")
        return parent_idx, frag_type

    def postprocess(self, root, harness_list):
        print_msg('self.postprocess', 'INFO', HELP_FILE)
        # Insert Load
        try:
            body = [get_define_node(self._seed_dir)]
            for jspath in harness_list:
                load_node = get_load_node(jspath)
                if load_node not in body:
                    try:
                        body.append(load_node)
                    except Exception as err:
                        print_msg('body.append(load_node)_ERR=' + str(err), 'ERROR', HELP_FILE)
            try:
                body.append(root)
                root = {
                    'type': 'Program',
                    'body': body,
                    'sourceType': 'script'
                }
                return root
            except Exception as err:
                print_msg('body.append(root)_ERR=' + str(err), 'ERROR', HELP_FILE)
                return None
        except Exception as err:
            print_msg('get_define_node_ERR=' + str(err), 'ERROR', HELP_FILE)
            return None

    def prepare_seed(self, model):
        print_msg('self.prepare_seed', 'INFO', HELP_FILE)
        # Prepare AST
        seed_name, frag_seq = self.select_seed()
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
            print_msg('model.run_ERR=' + str(err), 'ERROR', HELP_FILE)

    def push(self, stack, node):
        print_msg('self.push', 'INFO', HELP_FILE)
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

    def resolve_errors(self, root, harness_list):
        print_msg('self.resolve_errors', 'INFO', HELP_FILE)
        # ID Resolve
        try:
            symbols = hoisting(root, ([], []), True)
            resolve_id(root, None, symbols, True,
                       cand=[], hlist=harness_list)
        except ResolveBug as error:
            msg = 'Resolve Failed: {}'.format(error)
            print_msg(msg, 'WARN', HELP_FILE)

    def select_seed(self):
        print_msg('self.select_seed', 'INFO', HELP_FILE)
        seed_list = list(self._seed_dict.keys())
        frag_len = -1
        while frag_len < 3:
            seed_name = random.choice(seed_list)
            frag_seq, _ = self._seed_dict[seed_name]
            frag_len = len(frag_seq)
        return seed_name, frag_seq

    def traverse(self, node, frag_seq, stack):
        print_msg('self.traverse', 'INFO', HELP_FILE)
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


def fuzz(conf, mode=''):
    global HELP_FILE
    HELP_FILE = conf.help_dir + 'help_fuzz'
    if mode == 'single':
        print_msg('single_fuzz', 'INFO', HELP_FILE)
        run(0, conf, 'single_fuzz')
    else:
        print_msg('fuzz', 'INFO', HELP_FILE)
        try:
            set_start_method('spawn')
            try:
                p = Pool(conf.num_proc, init_worker)
                try:
                    pool_map(p, run, range(conf.num_proc), conf=conf)
                except Exception as err:
                    print_msg('set_start_method_ERR=' + str(err), 'ERROR', HELP_FILE)
            except Exception as err:
                print_msg('Pool_ERR=' + str(err), 'ERROR', HELP_FILE)
        except Exception as err:
            print_msg('pool_map_ERR=' + str(err), 'ERROR', HELP_FILE)


def is_pruned(node):
    print_msg('is_pruned', 'INFO', HELP_FILE)
    keys = node.keys()
    return (len(keys) == 1 and
            'type' in keys and
            get_node_type(node) not in TERM_TYPE)


def load_data(conf, proc_idx):
    print_msg('load_data(' + str(proc_idx) + ')', 'INFO', HELP_FILE)
    data_path = os.path.join(conf.data_dir,
                             'data.p')
    seed_data_path = os.path.join(conf.data_dir,
                                  'seed.p')

    seed = load_pickle(seed_data_path)
    data = load_pickle(data_path)
    return seed, data


def load_model(model_path, proc_idx):
    print_msg('load_model(' + str(proc_idx) + ')', 'INFO', HELP_FILE)
    try:
        model = torch.load(model_path, map_location=torch.device('cuda'))
        try:
            model.cuda()
            try:
                model.eval()
                return model
            except Exception as err:
                print_msg('model.eval_ERR=' + str(err), 'ERROR', HELP_FILE)
                sys.exit(1)
        except Exception as err:
            print_msg('model.cuda_ERR=' + str(err), 'ERROR', HELP_FILE)
            sys.exit(1)
    except Exception as err:
        print_msg('torch.load_ERR=' + str(err), 'ERROR', HELP_FILE)
        sys.exit(1)


def run(proc_idx, conf, mode=''):
    print_msg('run(' + str(proc_idx) + ')', 'INFO', HELP_FILE)
    if mode == 'single_fuzz':
        try:
            fuzzer = Fuzzer(proc_idx, conf, 'single_fuzz')
            try:
                fuzzer.fuzz(proc_idx)
            except Exception as err:
                print_msg('fuzzer.fuzz_ERR=' + str(err), 'ERROR', HELP_FILE)
                sys.exit(1)
        except Exception as err:
            print_msg('Fuzzer_INIT_ERR=' + str(err), 'ERROR', HELP_FILE)
            sys.exit(1)
    else:
        try:
            fuzzer = Fuzzer(proc_idx, conf)
            try:
                fuzzer.fuzz(proc_idx)
            except Exception as err:
                print_msg('fuzzer.fuzz_ERR=' + str(err), 'ERROR', HELP_FILE)
                sys.exit(1)
        except Exception as err:
            print_msg('Fuzzer_INIT_ERR=' + str(err), 'ERROR', HELP_FILE)
            sys.exit(1)
