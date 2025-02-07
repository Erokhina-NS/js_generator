import os

from subprocess import PIPE
from subprocess import Popen

from utils import list_dir
from utils import make_dir
from utils import print_msg

class Parser:
  def __init__(self):
    pass
  def parse(self,MAIN_PATH, seed_dir, ast_dir, help_dir):
    HELP_FILE = help_dir + 'help_preproc'
    js_list = list_dir(seed_dir)
    num_js = len(js_list)
    msg = 'Start parsing %d JS files' % (num_js)
    print_msg(msg, 'INFO', HELP_FILE, True)

    cmd = ['node', MAIN_PATH+'src/utils/parse.js']
    cmd += [seed_dir, ast_dir]
    #print_msg(str(cmd), 'MY', help_dir + 'help')
    parser = Popen(cmd, cwd='./',
                   stdin=PIPE, stdout=PIPE, stderr=PIPE)
    parser.wait()
    if parser.stderr.read() == b'':
        print_msg('Stop parsing JS files', 'INFO', HELP_FILE, True)
    else:
        print_msg('NOT parsing JS files: '+str(parser.stderr.read()), 'ERROR', HELP_FILE, True)
        sys.exit(1)


class SingleParser:
  def __init__(self, MAIN_PATH):
    cmd = ['node', MAIN_PATH+'src/utils/parse.js']
    self._parser = Popen(cmd, cwd='./', bufsize=0,
                         stdin=PIPE, stdout=PIPE, stderr=PIPE)

  def __del__(self):
    self._parser.terminate()

  def parse(self, js_path):
    js_path = str.encode(js_path + '\n')
    self._parser.stdin.write(js_path)
    ast_path = self._parser.stdout.readline()
    ast_path = ast_path.strip()
    return ast_path
