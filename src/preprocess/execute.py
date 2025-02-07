import os
import threading
from datetime import datetime
import pytz

from subprocess import PIPE, TimeoutExpired, Popen

from utils import kill_proc
from utils import list_dir
from utils import make_dir
from utils import pool_map
from utils import read
from utils import write
from utils import print_msg

HELP_FILE = ''
class Executor:
    def __init__(self, conf):
      self._conf = conf

    def const_log_path(self, js_path, log_dir):
      log_name = os.path.basename(js_path)
      log_name = '.'.join(log_name.split('.')[:-1])
      return os.path.join(log_dir, log_name)

    def execute(self, proc, log_path, timeout):
      timer = threading.Timer(timeout, lambda p: kill_proc(p), [proc])
      timer.start()
      stdout, stderr = proc.communicate()
      ret = proc.returncode

      self.write_log(log_path, stdout, stderr, ret)
      timer.cancel()
      
    def run(self, js_path, cwd):
      cmd = [self._conf.eng_exec]
      cmd += self._conf.opt
      cmd += [js_path]
      proc = Popen(cmd, cwd=cwd, stdout=PIPE, stderr=PIPE)
      log_path = self.const_log_path(js_path,
                                    self._conf.log_dir)
      self.execute(proc, log_path, self._conf.timeout)

    def write_log(self, log_path, stdout, stderr, ret):
      log = b'\n============== STDOUT ===============\n'
      log += stdout
      log += b'\n============== STDERR ===============\n'
      log += stderr
      log += b'\nMONTAGE_RETURN: %d' % (ret)
      try:
        write(log_path, log)
      except Exception as err:
        print('Error write because of err: '+str(err)+' file= '+log_path)
        pass

def exec_eng(js_path, conf):
    tmp_js_path = rewrite_file(js_path, conf.data_dir)

    executor = Executor(conf)
    cwd = os.path.dirname(js_path)
    try:
      executor.run(tmp_js_path, cwd)
    except Exception as err:
       print(err)

    os.remove(tmp_js_path)

def main(MAIN_PATH, pool, conf):
    global HELP_FILE
    HELP_FILE = conf.help_dir + '/help_preproc'
    js_list = []
    for js in list_dir(conf.seed_dir):
      if (js.endswith('.js') and
        os.path.getsize(js) < 30 * 1024):  # Excludes JS over 3KB
        js_list += [js]

    num_js = len(js_list)
    msg = 'Start executing %d JS files' % (num_js)
    print_msg(msg, 'INFO', HELP_FILE, True)
    time_start = datetime.now(pytz.timezone('Europe/Moscow'))
    print_msg('START_executing at TIME='+str(time_start.strftime("%H:%M:%S")),'INFO',HELP_FILE, True)
    pool_map(pool, exec_eng, js_list, conf=conf)
    time_stop = datetime.now(pytz.timezone('Europe/Moscow'))
    time_del = time_stop - time_start
    print_msg('STOP_executing at TIME='+str(time_stop.strftime("%H:%M:%S"))+',  DELTA= '+str(time_del),'INFO',HELP_FILE, True)

def rewrite_file(js_path, tmp_dir):
    dir_path = os.path.dirname(js_path)
    PREFIX = b'if(typeof load == \'undefined\') load = function(js_path){WScript.LoadScriptFile(\'%s/\'.concat(js_path));};'
    PREFIX = PREFIX % dir_path.encode('utf-8')

    code = read(js_path)
    code = b'\n'.join([PREFIX, code])

    js_name = os.path.basename(js_path)
    tmp_js_path = os.path.join(tmp_dir, js_name)

    write(tmp_js_path, code)

    return tmp_js_path

