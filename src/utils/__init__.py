import json
import os
import pickle
import shutil
import signal
import string
import torch
import ujson
import sys

from functools import partial
from hashlib import sha1
from random import choice
from utils.node import PROP_DICT

def data2tensor(batch, tensor_type='Long'):
    if tensor_type == 'Long':
        batch = torch.cuda.LongTensor(batch)
    elif tensor_type == 'Byte':
        batch = torch.cuda.ByteTensor(batch)
    elif tensor_type == 'Float':
        batch = torch.cuda.FloatTensor(batch)
    return batch

def get_node_type(node):
    return node['type']

def hash_frag(frag):
    return hash_val(stringify_frag(frag))

def hash_val(text):
    if type(text) is str:
        text = text.encode('utf-8')
    return sha1(text).hexdigest()

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def is_node_list(node):
    return type(node) == list

def is_single_node(node):
    return (type(node) == dict and
            'type' in node)

def kill_proc(proc):
    if proc.poll() is None:
        proc.kill()

def list_dir(dir_path):
    return [os.path.join(dir_path, f) for f in os.listdir(dir_path)]

def load_ast(ast_path):
    with open(ast_path, 'r') as f:
        try:
            ast = ujson.load(f)
        except Exception as e:
            dec = json.JSONDecoder()
            f.seek(0, 0)
            ast = f.read()
            ast = dec.decode(ast)
    js_name = os.path.basename(ast_path)[:-2]
    return js_name, ast

def load_pickle(dpath):
    with open(dpath, 'rb') as f:
        data = pickle.load(f)
    return data

def make_dir(dir_path, help=''):
    ans = 'yes'
    if os.path.exists(dir_path):
        msg = 'Do you want to delete %s? (yes/no/pass): ' % (dir_path)
        msg = get_msg(msg, 'WARN')
        ans = input(msg)
        if ans == 'yes':
            shutil.rmtree(dir_path)
            os.makedirs(dir_path)
            if help == 'help':
                with open(dir_path+'help', 'a+') as f:
                    f.write('\n')
                with open(dir_path+'help_preproc', 'a+') as f:
                    f.write('\n')
                with open(dir_path+'help_train', 'a+') as f:
                    f.write('\n')
                with open(dir_path+'help_fuzz', 'a+') as f:
                    f.write('\n')
        elif ans == 'pass':
            pass
        else:
            if ans != 'n':
                print_msg('Wrong Answer', 'ERROR', dir_path+'help', True)
            os._exit(1)
    else:
        os.makedirs(dir_path)
    return dir_path

def make_tmp_dir(dir_path):
    dir_path = os.path.join(dir_path, random_string(10))
    os.makedirs(dir_path)
    return dir_path

def pool_map(pool, func, list, **args):
    try:
        func = partial(func, **args)
        return pool.map(func, list)
    except KeyboardInterrupt:
        print_msg('Terminating workers ...', 'INFO')
        pool.terminate()
        pool.join()
        print_msg('Killed processes', 'INFO')
        os.killpg(os.getpid(), signal.SIGKILL)
    except Exception as err:
        print(err)
        sys.exit(1)

def random_string(length):
    candidate = string.ascii_letters + string.digits
    rand_str = [choice(candidate) for i in range(length)]
    return ''.join(rand_str)

def read(file_name, mode='rb', encoding=None):
    with open(file_name, mode, encoding=encoding) as f:
        return f.read()

def store_pickle(dpath, data):
    with open(dpath, 'wb') as f:
        pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)

def stringify_frag(node):
    str_val = ''
    if 'type' in node:
        node_type = get_node_type(node)
        prop_list = PROP_DICT[node_type]
    else:
        prop_list = sorted(node.keys())

    for key in prop_list:
        if key not in node: continue
        child = node[key]

        # If it has a single child
        if type(child) == dict:
            str_val += '{'
            str_val += stringify_frag(child)
            str_val += '}'
        # If it has multiple children
        elif type(child) == list:
            str_val += '['
            for _child in child:
                if _child is None:
                    str_val += str(None)
                else:
                    str_val += stringify_frag(_child)
            str_val += ']'
        # If it is a terminal
        else:
            str_val += str((key, node[key]))
    return str_val

def trim_seed_name(seed_name):
    if '_aug.js' in seed_name:
        return seed_name.replace('_aug.js', '.js')
    else:
        return seed_name

def write(file_name, content, mode='wb'):
    with open(file_name, mode) as f:
        if mode == 'wb':
            f.write(content)
        else:
            f.write(str(content)+'\n')


def write_ast(ast_path, ast):
    try:
        ast = json.dumps(ast, indent=2)
    except Exception as err:
        print_msg('json.dumps_err='+str(err), 'ERROR')
    try:
        ast = str.encode(ast)
    except Exception as err:
        print_msg('str.encode_err='+str(err), 'ERROR')
    try:
        write(ast_path, ast, mode='wb')
    except Exception as err:
        print_msg('write(ast_path)='+str(err), 'ERROR')


########################################################
class Colors:
    END = '\033[0m'
    ERROR = '\033[91m[ERROR] '
    INFO = '\033[94m[INFO] '
    WARN = '\033[93m[WARN] '
    MY = '\033[92m[MY] '

def get_color(msg_type):
    if msg_type == 'ERROR':
        return Colors.ERROR
    elif msg_type == 'INFO':
        return Colors.INFO
    elif msg_type == 'WARN':
        return Colors.WARN
    elif msg_type == 'MY':
        return Colors.MY
    else:
        return Colors.END

def get_msg(msg, msg_type=None):
    color = get_color(msg_type)
    msg = ''.join([color, str(msg), Colors.END])
    return msg

def print_msg(msg, msg_type=None, file=None, printer=False):
    if printer:
        if msg_type:
            msg2 = get_msg(msg, msg_type)
            print(msg2)  
            if file:
                write(file, '['+str(msg_type)+'] '+str(msg), 'a+')
        else:
            print(msg)
    else:
        pass
