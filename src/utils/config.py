import json
import os

from utils import read

class Config:
  def __init__(self, conf_path, MAIN_PATH):
    conf = self.load_conf(conf_path)
    self.main_path = MAIN_PATH
    self.src_path = self.main_path+conf['src_path']
    self.mode = conf['mode']
    self.seed_dir = self.main_path+conf['seed_dir']
    self.data_dir = self.main_path+'js_generator/data_'+conf['eng_name']
    self.ast_dir = os.path.join(self.data_dir, 'ast')
    self.log_dir = os.path.join(self.data_dir, 'log')
    self.help_dir = os.path.join(self.data_dir, 'help/')
    self.cov_res = self.help_dir + 'cov_res/'
    self.bug_dir = os.path.join(self.data_dir, 'bugs')
    self.eng_name = conf['eng_name']
    if self.eng_name == 'chakra':
        self.eng_path = self.main_path+'ChakraCore/'
        self.eng_cov = self.eng_path+'out/Release/'
        self.eng_exec = self.eng_path+'out/Release/ch'
        self.cov = 'CK_FIRST'
    elif self.eng_name == 'jerry':
        self.eng_path = self.main_path+'jerryscript/'
        self.eng_cov = self.eng_path+'build/'
        self.eng_exec = self.eng_path+'build/bin/jerry'
        self.cov = 'jerry_FIRST'
    elif self.eng_name == 'jsc':
        self.eng_path = self.main_path+'WebKit/'
        self.eng_cov = self.eng_path+'CovBuild/'
        self.eng_exec = self.eng_path+'CovBuild/bin/jsc'
        self.cov = 'JSC_FIRST'    
    elif self.eng_name == 'v8':
        self.eng_path = self.main_path+'v8/'  
        self.eng_cov = self.eng_path+'fuzzbuild/'
        self.eng_exec = self.eng_path+'fuzzbuild/d8'
        self.cov = 'V8_FIRST'
    self.emb_size = conf['model']['emb_size']
    self.batch_size = conf['model']['batch_size']
    self.epoch = conf['model']['epoch']
    self.gamma = conf['model']['gamma']
    self.lr = conf['model']['lr']
    self.max_ins = conf['max_ins']
    self.momentum = conf['model']['momentum']
    self.split_size = conf['model']['split_size']
    self.weight_decay = conf['model']['weight_decay']
    self.num_gpu = conf['num_gpu']
    self.num_proc = conf['num_proc']
    self.opt = conf['opt']
    self.timeout = conf['timeout']
    self.top_k = conf['top_k']


  def load_conf(self, conf_path):
    conf = read(conf_path, 'r')
    dec = json.JSONDecoder()
    conf = dec.decode(conf)
    return conf
