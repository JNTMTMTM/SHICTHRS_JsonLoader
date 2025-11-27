
import json
import base64
import hashlib
import hmac
from copy import deepcopy
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad
from Crypto.Hash import Poly1305
from ..hash.SHRJsonLoader_en_md5_hexdigest import en_md5hash_code

def encrypt_with_key_b4(data : str , key : str) -> str:
    encrypted_data = []
    key_length = len(key)
    for i, char in enumerate(data):
        encrypted_char = chr(ord(char) ^ ord(key[i % key_length]))
        encrypted_data.append(encrypted_char)
    
    encrypted_str = ''.join(encrypted_data)
    return base64.b64encode(encrypted_str.encode('utf-8')).decode('utf-8')

def encrypt_with_key_b0(data : str , key : str) -> str:
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
    nonce = hashlib.sha256(key.encode('utf-8') + data.encode('utf-8')).digest()[:12]
    cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
    ciphertext = cipher.encrypt(data.encode('utf-8'))
    mac = Poly1305.new(key=key_bytes, cipher=ChaCha20, nonce=nonce).update(ciphertext).digest()
    encrypted_data = nonce + ciphertext + mac
    return base64.b64encode(encrypted_data).decode('utf-8')

def encrypt_with_key_b1(data : str , key : str) -> str:
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
    nonce = hashlib.sha256(key.encode('utf-8') + data.encode('utf-8')).digest()[:12]
    cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
    ciphertext = cipher.encrypt(data.encode('utf-8'))
    encrypted_data = nonce + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def encrypt_with_key_b2(data : str , key : str) -> str:
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def encrypt_with_key_b3(data : str , key : str) -> str:
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
    hmac_obj = hmac.new(key_bytes, data.encode('utf-8'), hashlib.sha256)
    encrypted_data = hmac_obj.digest()
    combined = data.encode('utf-8') + b'|' + base64.b64encode(encrypted_data)
    return base64.b64encode(combined).decode('utf-8')

def generate_key_hash_b4(original_key : str , key : str) -> str:
    key_hash = en_md5hash_code(original_key)[:8]
    encrypted_key = encrypt_with_key_b4(original_key, key)
    return f"{encrypted_key}_{key_hash}"

def generate_key_hash_b0(original_key : str , key : str) -> str:
    key_hash = en_md5hash_code(original_key)[:8]
    encrypted_key = encrypt_with_key_b0(original_key, key)
    return f"{encrypted_key}_{key_hash}"

def generate_key_hash_b1(original_key : str , key : str) -> str:
    key_hash = en_md5hash_code(original_key)[:8]
    encrypted_key = encrypt_with_key_b1(original_key, key)
    return f"{encrypted_key}_{key_hash}"

def generate_key_hash_b2(original_key : str , key : str) -> str:
    key_hash = en_md5hash_code(original_key)[:8]
    encrypted_key = encrypt_with_key_b2(original_key, key)
    return f"{encrypted_key}_{key_hash}"

def generate_key_hash_b3(original_key : str , key : str) -> str:
    key_hash = en_md5hash_code(original_key)[:8]
    encrypted_key = encrypt_with_key_b3(original_key, key)
    return f"{encrypted_key}_{key_hash}"

def encrypt_dict_keys_and_values_b4(data_dict : dict , key : str) -> dict:
    encrypted_dict = {}
    for original_key, value in data_dict.items():
        encrypted_key = generate_key_hash_b4(original_key, key)
        
        if isinstance(value, dict):
            encrypted_dict[encrypted_key] = encrypt_dict_keys_and_values_b4(value, key)
        elif isinstance(value, (list, tuple)):
            encrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    encrypted_list.append(encrypt_dict_keys_and_values_b4(item, key))
                elif isinstance(item, str):
                    encrypted_list.append(encrypt_with_key_b4(item, key))
                else:
                    encrypted_list.append(encrypt_with_key_b4(str(item), key))
            encrypted_dict[encrypted_key] = encrypted_list
        elif isinstance(value, str):
            encrypted_dict[encrypted_key] = encrypt_with_key_b4(value, key)
        else:
            encrypted_dict[encrypted_key] = encrypt_with_key_b4(str(value), key)
    
    return encrypted_dict

def encrypt_dict_keys_and_values_b0(data_dict : dict , key : str) -> dict:
    encrypted_dict = {}
    for original_key, value in data_dict.items():
        encrypted_key = generate_key_hash_b0(original_key, key)
        
        if isinstance(value, dict):
            encrypted_dict[encrypted_key] = encrypt_dict_keys_and_values_b0(value, key)
        elif isinstance(value, (list, tuple)):
            encrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    encrypted_list.append(encrypt_dict_keys_and_values_b0(item, key))
                elif isinstance(item, str):
                    encrypted_list.append(encrypt_with_key_b0(item, key))
                else:
                    encrypted_list.append(encrypt_with_key_b0(str(item), key))
            encrypted_dict[encrypted_key] = encrypted_list
        elif isinstance(value, str):
            encrypted_dict[encrypted_key] = encrypt_with_key_b0(value, key)
        else:
            encrypted_dict[encrypted_key] = encrypt_with_key_b0(str(value), key)
    
    return encrypted_dict

def encrypt_dict_keys_and_values_b1(data_dict : dict , key : str) -> dict:
    encrypted_dict = {}
    for original_key, value in data_dict.items():
        encrypted_key = generate_key_hash_b1(original_key, key)
        
        if isinstance(value, dict):
            encrypted_dict[encrypted_key] = encrypt_dict_keys_and_values_b1(value, key)
        elif isinstance(value, (list, tuple)):
            encrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    encrypted_list.append(encrypt_dict_keys_and_values_b1(item, key))
                elif isinstance(item, str):
                    encrypted_list.append(encrypt_with_key_b1(item, key))
                else:
                    encrypted_list.append(encrypt_with_key_b1(str(item), key))
            encrypted_dict[encrypted_key] = encrypted_list
        elif isinstance(value, str):
            encrypted_dict[encrypted_key] = encrypt_with_key_b1(value, key)
        else:
            encrypted_dict[encrypted_key] = encrypt_with_key_b1(str(value), key)
    
    return encrypted_dict

def encrypt_dict_keys_and_values_b2(data_dict : dict , key : str) -> dict:
    encrypted_dict = {}
    for original_key, value in data_dict.items():
        encrypted_key = generate_key_hash_b2(original_key, key)
        
        if isinstance(value, dict):
            encrypted_dict[encrypted_key] = encrypt_dict_keys_and_values_b2(value, key)
        elif isinstance(value, (list, tuple)):
            encrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    encrypted_list.append(encrypt_dict_keys_and_values_b2(item, key))
                elif isinstance(item, str):
                    encrypted_list.append(encrypt_with_key_b2(item, key))
                else:
                    encrypted_list.append(encrypt_with_key_b2(str(item), key))
            encrypted_dict[encrypted_key] = encrypted_list
        elif isinstance(value, str):
            encrypted_dict[encrypted_key] = encrypt_with_key_b2(value, key)
        else:
            encrypted_dict[encrypted_key] = encrypt_with_key_b2(str(value), key)
    
    return encrypted_dict

def encrypt_dict_keys_and_values_b3(data_dict : dict , key : str) -> dict:
    encrypted_dict = {}
    for original_key, value in data_dict.items():
        encrypted_key = generate_key_hash_b3(original_key, key)
        
        if isinstance(value, dict):
            encrypted_dict[encrypted_key] = encrypt_dict_keys_and_values_b3(value, key)
        elif isinstance(value, (list, tuple)):
            encrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    encrypted_list.append(encrypt_dict_keys_and_values_b3(item, key))
                elif isinstance(item, str):
                    encrypted_list.append(encrypt_with_key_b3(item, key))
                else:
                    encrypted_list.append(encrypt_with_key_b3(str(item), key))
            encrypted_dict[encrypted_key] = encrypted_list
        elif isinstance(value, str):
            encrypted_dict[encrypted_key] = encrypt_with_key_b3(value, key)
        else:
            encrypted_dict[encrypted_key] = encrypt_with_key_b3(str(value), key)
    
    return encrypted_dict

def write_json_file(json_dict : dict , path : str , ectype : str , key : str , verify : bool = False) -> None:
    if ectype is None or ectype == '':
        with open(path , "w" , encoding = "utf-8") as f:
            json.dump(json_dict , f , ensure_ascii = False)
            f.close()
    elif ectype == 'b0':
        if not key:
            raise ValueError(f"SHRJsonLoaderException [ERROR.1009] json file enkey not found. File Path : {path}")
        encrypted_dict = encrypt_dict_keys_and_values_b0(deepcopy(json_dict), key)
        
        encrypted_dict["_SHR_ECTYPE"] = ectype
        
        verification_token = encrypt_with_key_b0(key, key)
        encrypted_dict["_SHR_VERIFICATION"] = verification_token
        
        # 添加数据完整性验证
        original_data_str = json.dumps(json_dict, sort_keys=True, ensure_ascii=False)
        data_hash = en_md5hash_code(original_data_str)
        encrypted_hash = encrypt_with_key_b0(data_hash, key)
        encrypted_dict["_SHR_DATA_HASH"] = encrypted_hash
        
        if verify:
            # 添加整个文件的哈希值（在添加所有系统键后计算）
            # 先创建一个临时副本，不包含文件哈希值
            temp_dict = {k: v for k, v in encrypted_dict.items() if k != "_SHR_FILE_HASH"}
            
            # 计算临时字典的哈希值
            temp_dict_str = json.dumps(temp_dict, sort_keys=True, ensure_ascii=False)
            file_hash = en_md5hash_code(temp_dict_str)
            
            # 加密文件哈希值
            encrypted_file_hash = encrypt_with_key_b0(file_hash, key)
            encrypted_dict["_SHR_FILE_HASH"] = encrypted_file_hash
        
        with open(path , "w" , encoding = "utf-8") as f:
            json.dump(encrypted_dict , f , ensure_ascii = False)
            f.close()
    elif ectype == 'b1':
        if not key:
            raise ValueError(f"SHRJsonLoaderException [ERROR.1009] json file enkey not found. File Path : {path}")
        encrypted_dict = encrypt_dict_keys_and_values_b1(deepcopy(json_dict), key)
        
        encrypted_dict["_SHR_ECTYPE"] = ectype
        
        verification_token = encrypt_with_key_b1(key, key)
        encrypted_dict["_SHR_VERIFICATION"] = verification_token
        
        # 添加数据完整性验证
        original_data_str = json.dumps(json_dict, sort_keys=True, ensure_ascii=False)
        data_hash = en_md5hash_code(original_data_str)
        encrypted_hash = encrypt_with_key_b1(data_hash, key)
        encrypted_dict["_SHR_DATA_HASH"] = encrypted_hash
        
        if verify:
            # 添加整个文件的哈希值（在添加所有系统键后计算）
            # 先创建一个临时副本，不包含文件哈希值
            temp_dict = {k: v for k, v in encrypted_dict.items() if k != "_SHR_FILE_HASH"}
            
            # 计算临时字典的哈希值
            temp_dict_str = json.dumps(temp_dict, sort_keys=True, ensure_ascii=False)
            file_hash = en_md5hash_code(temp_dict_str)
            
            # 加密文件哈希值
            encrypted_file_hash = encrypt_with_key_b1(file_hash, key)
            encrypted_dict["_SHR_FILE_HASH"] = encrypted_file_hash
        
        with open(path , "w" , encoding = "utf-8") as f:
            json.dump(encrypted_dict , f , ensure_ascii = False)
            f.close()
    elif ectype == 'b2':
        if not key:
            raise ValueError(f"SHRJsonLoaderException [ERROR.1009] json file enkey not found. File Path : {path}")
        encrypted_dict = encrypt_dict_keys_and_values_b2(deepcopy(json_dict), key)
        
        encrypted_dict["_SHR_ECTYPE"] = ectype
        
        verification_token = encrypt_with_key_b2(key, key)
        encrypted_dict["_SHR_VERIFICATION"] = verification_token
        
        # 添加数据完整性验证
        original_data_str = json.dumps(json_dict, sort_keys=True, ensure_ascii=False)
        data_hash = en_md5hash_code(original_data_str)
        encrypted_hash = encrypt_with_key_b2(data_hash, key)
        encrypted_dict["_SHR_DATA_HASH"] = encrypted_hash
        
        if verify:
            # 添加整个文件的哈希值（在添加所有系统键后计算）
            # 先创建一个临时副本，不包含文件哈希值
            temp_dict = {k: v for k, v in encrypted_dict.items() if k != "_SHR_FILE_HASH"}
            
            # 计算临时字典的哈希值
            temp_dict_str = json.dumps(temp_dict, sort_keys=True, ensure_ascii=False)
            file_hash = en_md5hash_code(temp_dict_str)
            
            # 加密文件哈希值
            encrypted_file_hash = encrypt_with_key_b2(file_hash, key)
            encrypted_dict["_SHR_FILE_HASH"] = encrypted_file_hash
        
        with open(path , "w" , encoding = "utf-8") as f:
            json.dump(encrypted_dict , f , ensure_ascii = False)
            f.close()
    elif ectype == 'b3':
        if not key:
            raise ValueError(f"SHRJsonLoaderException [ERROR.1009] json file enkey not found. File Path : {path}")
        encrypted_dict = encrypt_dict_keys_and_values_b3(deepcopy(json_dict), key)
        
        encrypted_dict["_SHR_ECTYPE"] = ectype
        
        verification_token = encrypt_with_key_b3(key, key)
        encrypted_dict["_SHR_VERIFICATION"] = verification_token
        
        # 添加数据完整性验证
        original_data_str = json.dumps(json_dict, sort_keys=True, ensure_ascii=False)
        data_hash = en_md5hash_code(original_data_str)
        encrypted_hash = encrypt_with_key_b3(data_hash, key)
        encrypted_dict["_SHR_DATA_HASH"] = encrypted_hash
        
        if verify:
            # 添加整个文件的哈希值（在添加所有系统键后计算）
            # 先创建一个临时副本，不包含文件哈希值
            temp_dict = {k: v for k, v in encrypted_dict.items() if k != "_SHR_FILE_HASH"}
            
            # 计算临时字典的哈希值
            temp_dict_str = json.dumps(temp_dict, sort_keys=True, ensure_ascii=False)
            file_hash = en_md5hash_code(temp_dict_str)
            
            # 加密文件哈希值
            encrypted_file_hash = encrypt_with_key_b3(file_hash, key)
            encrypted_dict["_SHR_FILE_HASH"] = encrypted_file_hash
        
        with open(path , "w" , encoding = "utf-8") as f:
            json.dump(encrypted_dict , f , ensure_ascii = False)
            f.close()
    elif ectype == 'b4':
        if not key:
            raise ValueError(f"SHRJsonLoaderException [ERROR.1009] json file enkey not found. File Path : {path}")
        encrypted_dict = encrypt_dict_keys_and_values_b4(deepcopy(json_dict), key)
        
        encrypted_dict["_SHR_ECTYPE"] = ectype
        
        verification_token = encrypt_with_key_b4(key, key)
        encrypted_dict["_SHR_VERIFICATION"] = verification_token
        
        # 添加数据完整性验证
        original_data_str = json.dumps(json_dict, sort_keys=True, ensure_ascii=False)
        data_hash = en_md5hash_code(original_data_str)
        encrypted_hash = encrypt_with_key_b4(data_hash, key)
        encrypted_dict["_SHR_DATA_HASH"] = encrypted_hash
        
        if verify:
            # 添加整个文件的哈希值（在添加所有系统键后计算）
            # 先创建一个临时副本，不包含文件哈希值
            temp_dict = {k: v for k, v in encrypted_dict.items() if k != "_SHR_FILE_HASH"}
            
            # 计算临时字典的哈希值
            temp_dict_str = json.dumps(temp_dict, sort_keys=True, ensure_ascii=False)
            file_hash = en_md5hash_code(temp_dict_str)
            
            # 加密文件哈希值
            encrypted_file_hash = encrypt_with_key_b4(file_hash, key)
            encrypted_dict["_SHR_FILE_HASH"] = encrypted_file_hash
        
        with open(path , "w" , encoding = "utf-8") as f:
            json.dump(encrypted_dict , f , ensure_ascii = False)
            f.close()
    else:
        raise ValueError(f"SHRJsonLoaderException [ERROR.1013] unsupported encryption type: {ectype}. Supported types: 'b0', 'b1', 'b2', 'b3', 'b4' or None")