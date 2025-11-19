
from nt import read
import os
from colorama import init
init()
from .utils.json.SHRJsonLoader_read_json_file import read_json_file
from .utils.json.SHRJsonLoader_write_json_file import write_json_file

print('\033[1mWelcome to use SHRJsonLoader - json file io System\033[0m\n|  \033[1;34mGithub : https://github.com/JNTMTMTM/SHICTHRS_JsonLoader\033[0m')
print('|  \033[1mAlgorithms = rule ; Questioning = approval\033[0m')
print('|  \033[1mCopyright : © 2025-2026 SHICTHRS, Std. All rights reserved.\033[0m\n')

class SHRJsonLoaderException(BaseException):
    def __init__(self , message: str) -> None:
        self.message = message
    
    def __str__(self):
        return self.message

def SHRJsonLoader_read_json_file(path : str , ectype : str = None , key : str = None , verify : bool = False) -> dict:
    try:
        if os.path.exists(path):
            if os.path.isfile(path) and path.endswith('.json'):
                return read_json_file(path)
            else:
                raise Exception(f"SHRJsonLoader [ERROR.1004] only json file is supported not .{path.split('.')[-1]}. File Path : {path} NOT FOUND")
        else:
            raise Exception(f"SHRJsonLoader [ERROR.1005] unable to find json file. File Path : {path} NOT FOUND")
    except Exception as e:
        raise SHRJsonLoaderException(f"SHRJsonLoader [ERROR.1006] unable to read json file. File Path : {path} | {e}")

def SHRJsonLoader_write_json_file(json_dict : dict , path : str , ectype : str = None , key : str = None , verify : bool = False) -> None:
    try:
        pass
    except Exception as e:
        raise SHRJsonLoaderException(f"SHRJsonLoader [ERROR.1007] unable to write json file. File Path : {path} | {e}")

