# *-* coding: utf-8 *-*
# src\__init__.py
# SHICTHRS JSON LOADER
# AUTHOR : SHICTHRS-JNTMTMTM
# Copyright : © 2025-2026 SHICTHRS, Std. All rights reserved.
# lICENSE : GPL-3.0

import os
from colorama import init
init()
from .utils.json.SHRJsonLoader_read_json_file import read_json_file
from .utils.json.SHRJsonLoader_write_json_file import write_json_file

print('\033[1mWelcome to use SHRJsonLoader - json file io System\033[0m\n|  \033[1;34mGithub : https://github.com/JNTMTMTM/SHICTHRS_JsonLoader\033[0m')
print('|  \033[1mAlgorithms = rule ; Questioning = approval\033[0m')
print('|  \033[1mCopyright : © 2025-2026 SHICTHRS, Std. All rights reserved.\033[0m\n')

__all__ = ['SHRJsonLoader_read_json_file' , 'SHRJsonLoader_write_json_file']

ENCRYPTION_TYPES : dict = {'zh-cn' : ['B0-ChaCha20-Poly1305 认证加密' ,
                            'B1-ChaCha20 流加密' ,
                            'B2-AES-CBC 块加密' ,
                            'B3-HMAC-SHA256 认证' ,
                            'B4-XOR 异或加密'] ,
                        'en' : ['B0-ChaCha20-Poly1305 Authenticated Encryption' ,
                            'B1-ChaCha20 Stream Encryption' ,
                            'B2-AES-CBC Block Encryption' ,
                            'B3-HMAC-SHA256 Authentication' ,
                            'B4-XOR Encryption'] ,
                            }

class SHRJsonLoaderException(BaseException):
    def __init__(self , message: str) -> None:
        self.message = message
    
    def __str__(self):
        return self.message

def SHRJsonLoader_read_json_file(path : str , ectype : str = None , key : str = None , verify : bool = False) -> dict:
    try:
        if os.path.exists(path):
            if os.path.isfile(path) and path.endswith('.json'):
                return read_json_file(path , ectype , key , verify)
            else:
                raise SHRJsonLoaderException(f"SHRJsonLoader [ERROR.1004] only json file is supported not .{path.split('.')[-1]}.")
        else:
            raise SHRJsonLoaderException(f"SHRJsonLoader [ERROR.1005] unable to find json file. File Path : {path} NOT FOUND")
    except Exception as e:
        raise SHRJsonLoaderException(f"SHRJsonLoader [ERROR.1006] unable to read json file. File Path : {path} | {e}")

def SHRJsonLoader_write_json_file(json_dict : dict , path : str , ectype : str = None , key : str = None , verify : bool = False) -> None:
    try:
        if not isinstance(json_dict, dict):
            raise SHRJsonLoaderException(f"SHRJsonLoader [ERROR.1015] json_dict parameter must be a dictionary, got {type(json_dict).__name__}")
            
        if path.endswith('.json'):
            write_json_file(json_dict , path , ectype , key , verify)
        else:
            raise SHRJsonLoaderException(f"SHRJsonLoader [ERROR.1007] only json file is supported not .{path.split('.')[-1]}.")
    except Exception as e:
        raise SHRJsonLoaderException(f"SHRJsonLoader [ERROR.1008] unable to write json file. File Path : {path} | {e}")

