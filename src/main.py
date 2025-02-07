import argparse
import os
import sys
import torch

from utils import write, make_dir
from utils.config import Config
from utils import print_msg



def build_map(conf):
    from utils.map import build_id_map
    build_id_map(conf)

def exec_fuzz(conf, mode=''):
    if not os.path.exists('fuzz/id_map.py'):
        print_msg('Please build a map for identifiers predefined in the harness files first.',
              'ERROR', conf.help_dir+'help_fuzz')
        sys.exit(1)

    cuda=torch.device('cuda')
    from fuzz.fuzz import fuzz
    if mode == 'single':
        fuzz(conf, 'single')
    else:
        fuzz(conf)

def exec_preprocess(conf):
    from preprocess.preprocess import Preprocessor
    preprocessor = Preprocessor(conf)
    preprocessor.preprocess()

def exec_train(conf):
    from train.train import ModelTrainer
    cuda=torch.device('cuda')
    trainer = ModelTrainer(conf)
    trainer.train()

def get_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--opt', required=True,
                          choices=['preprocess', 'train', 'fuzz', 'build_map','single_fuzz'])
    arg_parser.add_argument('--config', required=True)
    return arg_parser.parse_args(sys.argv[1:])

def main():   
    # Increase max recursion depth limit
    sys.setrecursionlimit(10000)

    args = get_args()
    config_path = args.config
    conf = Config(config_path)
    make_dir(conf.help_dir,'help')
    print_msg('START\n','INFO', conf.help_dir+'help', True)
    if not torch.cuda.is_available():
        print_msg('Montage only supports CUDA-enabled machines',
              'ERROR', conf.help_dir+'help', True)
        sys.exit(1)
    else:
        if args.opt == 'preprocess':
            exec_preprocess(conf)
        elif args.opt == 'train':
            exec_train(conf)
        elif args.opt == 'single_fuzz':
            exec_fuzz(conf, 'single')
        elif args.opt == 'fuzz':
            exec_fuzz(conf)
        elif args.opt == 'build_map':
            build_map(conf)

if __name__ == '__main__':
    main()
