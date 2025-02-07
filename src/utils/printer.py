import os
import json
from subprocess import PIPE,Popen

from utils import hash_frag, write 

def write_ast_to_file(ast_path, ast):
    try:
        ast = json.dumps(ast, indent=2)
        try:
            ast = ast.encode('utf-8')
            try:
                write(ast_path, ast)
            except Exception as err:
                pass
        except Exception as err:
            pass
    except Exception as err:
        pass


class CodePrinter:
    def __init__(self, js_dir, utils_path):
        self._js_dir = js_dir
        cmd = ['node', utils_path+'utils/ast2code.js', js_dir]
        self._printer = Popen(cmd, cwd='./', bufsize=0,
                              stdin=PIPE, stdout=PIPE, stderr=PIPE)

    def __del__(self):
        self._printer.terminate()

    def ast2code(self, ast):
        ast_name = hash_frag(ast) + '.json'
        ast_path = os.path.join(self._js_dir, ast_name)
        try:
            write_ast_to_file(ast_path, ast)
            try:
                ast_path = (ast_path + '\n').encode('utf-8')  
                try:
                    self._printer.stdin.write(ast_path)
                    try:
                        js_path = self._printer.stdout.readline()
                        try:
                            js_path = js_path.decode('utf-8').strip()
                            try:
                                os.remove(ast_path.strip())
                            except Exception as err:
                                print('os.remove_err=' + str(err))
                                return None
                            if 'Error' in js_path:
                                return None
                            else:
                                return js_path
                        except Exception as err:
                            return None
                    except Exception as err:
                        return None
                except Exception as err:
                    print('self._printer.stdin.write_err=' + str(err))
                    return None
            except Exception as err:
                print('str.encode_err=' + str(err), 'ERROR')
                return None
        except Exception as err:
            print('write_ast_to_file_err=' + str(err))
            return None

