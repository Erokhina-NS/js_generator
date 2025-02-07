import os, sys
from multiprocessing import Pool
from datetime import datetime
import pytz

from preprocess import aggregate
from preprocess import execute
from preprocess import fragmentize
from preprocess import normalize
from preprocess import oov
from preprocess import strip
from preprocess import triage
from utils import init_worker
from utils import make_dir
from utils import store_pickle
from utils import print_msg
from utils import list_dir
from utils.parse import Parser
from utils.config import Config

MAIN_PATH = '/home/jovyan/'

class Preprocessor:
    def __init__(self, conf):
        self._conf = conf
        self._pool = Pool(conf.num_proc, init_worker)
        self._ast_dir = os.path.join(conf.data_dir, 'ast')
        self._seed_dir = os.path.join(conf.data_dir, 'seed')
        self._main_path = conf.main_path+'js_generator/'
        self._help_dir = conf.help_dir

    def remove_js_with_errors(self):
        execute.main(self._main_path,self._pool, self._conf)
        triage.main(self._conf)

    def parse(self):
        make_dir(self._ast_dir)
        parser = Parser()
        parser.parse(self._main_path, self._seed_dir, self._ast_dir, self._help_dir)

    def strip_eval(self):
        strip.main(self._pool, self._conf)

    def normalize_ast(self):
        normalize.main(self._pool, self._conf)

    def fragment_ast(self):
        return fragmentize.main(self._pool, self._conf)

    def aggregate_frags(self, ast_data):
        aggregated_data = aggregate.main(ast_data,self._conf)
        (self._seed_dict,
         self._frag_dict, self._frag_list,
         self._type_dict, self._type_list) = aggregated_data

    def mark_oov(self):
        renewed_data = oov.replace_uncommon(self._seed_dict,
                                            self._frag_list,
                                            self._frag_dict,
                                            self._help_dir)
        (self._new_seed_dict,
         self._new_frag_dict, self._new_frag_list,
         self._oov_pool) = renewed_data

    def preprocess(self):
        HELP_FILE = self._help_dir+'help_preproc'
        time_start = datetime.now(pytz.timezone('Europe/Moscow'))
        print_msg('[1/8] Filtering out JS with errors at TIME='+str(time_start.strftime("%H:%M:%S"))+'\n','INFO',HELP_FILE, True)
        self.remove_js_with_errors()        
        print_msg('Seed files COUNT='+str(len(list_dir(self._seed_dir))),'INFO', HELP_FILE, True)
        time_start2 = datetime.now(pytz.timezone('Europe/Moscow'))
        time_del = time_start2 - time_start
        print_msg('STOP_preprocessing at TIME='+str(time_start2.strftime("%H:%M:%S"))+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)
        
        print_msg('[2/8] Parsing JS code into ASTs','INFO',HELP_FILE, True)
        self.parse()
        time_start3 = datetime.now(pytz.timezone('Europe/Moscow'))
        time_del = time_start3 - time_start2
        print_msg('STOP_parsing at TIME='+str(time_start3.strftime("%H:%M:%S"))+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)
        
        print_msg('[3/8] Stripping args of eval func calls','INFO',HELP_FILE,True)
        self.strip_eval()
        time_start4 = datetime.now(pytz.timezone('Europe/Moscow'))
        time_del = time_start4 - time_start3
        print_msg('STOP_stripping at TIME='+str(time_start4.strftime("%H:%M:%S"))+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)
        
        print_msg('[4/8] Normalizing identifiers','INFO',HELP_FILE,True)
        self.normalize_ast()
        time_start5 = datetime.now(pytz.timezone('Europe/Moscow'))
        time_del = time_start5 - time_start4
        print_msg('STOP_normalizing at TIME='+str(time_start5.strftime("%H:%M:%S"))+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)
        
        print_msg('[5/8] Fragmentizing JS ASTs','INFO',HELP_FILE,True)
        ast_data = self.fragment_ast()
        time_start6 = datetime.now(pytz.timezone('Europe/Moscow'))
        time_del = time_start6 - time_start5
        print_msg('STOP_fragmentizing at TIME='+str(time_start6.strftime("%H:%M:%S"))+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)
        
        print_msg('[6/8] Aggregating fragments','INFO',HELP_FILE,True)
        self.aggregate_frags(ast_data)
        self._pool.terminate()
        time_start7 = datetime.now(pytz.timezone('Europe/Moscow'))
        time_del = time_start7 - time_start6
        print_msg('STOP_aggregating at TIME='+str(time_start7.strftime("%H:%M:%S"))+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)
        
        print_msg('[7/8] Replacing uncommon fragments','INFO',HELP_FILE,True)
        self.mark_oov()
        time_start8 = datetime.now(pytz.timezone('Europe/Moscow'))
        time_del = time_start8 - time_start7
        print_msg('STOP_replacing at TIME='+str(time_start8.strftime("%H:%M:%S"))+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)
        
        print_msg('[8/8] Writing data into files','INFO',HELP_FILE,True)
        self.write_data()  
        time_start9 = datetime.now(pytz.timezone('Europe/Moscow'))
        time_del = time_start9 - time_start8
        print_msg('STOP_writing at TIME='+str(time_start9.strftime("%H:%M:%S"))+"\n"+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)

    def write_data(self):
        data_path = os.path.join(self._conf.data_dir,
                                 'data.p')
        train_data_path = os.path.join(self._conf.data_dir,
                                       'train_data.p')
        seed_data_path = os.path.join(self._conf.data_dir,
                                      'seed.p')

        # Write a seed file
        seed = (self._seed_dict, self._frag_list,
                self._new_seed_dict)
        store_pickle(seed_data_path, seed)

        # Write a train data file
        train_data = (self._new_seed_dict,
                      self._new_frag_list,
                      self._type_list,
                      self._type_dict)
        store_pickle(train_data_path, train_data)

        # Write a data file
        data = (self._new_frag_list, self._new_frag_dict,
                self._oov_pool, self._type_dict)
        store_pickle(data_path, data)

def main():  
    conf = Config(MAIN_PATH+'js_generator/conf-jerry.json',MAIN_PATH)
    make_dir(conf.help_dir)
    make_dir(conf.log_dir)
    make_dir(conf.ast_dir)
    make_dir(conf.bug_dir)
    preprocessor = Preprocessor(conf)
    preprocessor.preprocess()

if __name__ == '__main__':
    main()
