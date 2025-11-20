
import json
import base64
from copy import deepcopy
from ..hash.SHRJsonLoader_en_md5_hexdigest import en_md5hash_code

def encrypt_with_key(data : str , key : str) -> str:
    """使用密钥对数据进行加密
    Args:
        data: 要加密的数据
        key: 加密密钥
    Returns:
        加密后的base64字符串
    """
    if not key:
        return data
    
    # 简单的异或加密
    encrypted_data = []
    key_length = len(key)
    for i, char in enumerate(data):
        encrypted_char = chr(ord(char) ^ ord(key[i % key_length]))
        encrypted_data.append(encrypted_char)
    
    encrypted_str = ''.join(encrypted_data)
    # 将加密后的数据进行base64编码
    return base64.b64encode(encrypted_str.encode('utf-8')).decode('utf-8')

def generate_key_hash(original_key : str , key : str) -> str:
    """为键生成哈希值并与加密后的键组合
    Args:
        original_key: 原始键
        key: 加密密钥
    Returns:
        加密后的键+哈希值
    """
    # 生成原始键的MD5哈希值
    key_hash = en_md5hash_code(original_key)[:8]  # 取前8位
    
    # 加密原始键
    encrypted_key = encrypt_with_key(original_key, key)
    
    # 组合加密键和哈希值
    return f"{encrypted_key}_{key_hash}"

def encrypt_dict_keys_and_values(data_dict : dict , key : str) -> dict:
    """递归地对字典中的所有键和值进行加密，为每个键添加哈希值
    Args:
        data_dict: 要加密的字典
        key: 加密密钥
    Returns:
        加密后的字典
    """
    encrypted_dict = {}
    for original_key, value in data_dict.items():
        # 生成加密后的键+哈希值
        encrypted_key = generate_key_hash(original_key, key)
        
        if isinstance(value, dict):
            # 如果值是字典，递归处理
            encrypted_dict[encrypted_key] = encrypt_dict_keys_and_values(value, key)
        elif isinstance(value, (list, tuple)):
            # 如果值是列表或元组，处理每个元素
            encrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    encrypted_list.append(encrypt_dict_keys_and_values(item, key))
                elif isinstance(item, str):
                    encrypted_list.append(encrypt_with_key(item, key))
                else:
                    # 非字符串类型转换为字符串后再加密
                    encrypted_list.append(encrypt_with_key(str(item), key))
            encrypted_dict[encrypted_key] = encrypted_list
        elif isinstance(value, str):
            # 字符串值直接加密
            encrypted_dict[encrypted_key] = encrypt_with_key(value, key)
        else:
            # 非字符串类型转换为字符串后再加密
            encrypted_dict[encrypted_key] = encrypt_with_key(str(value), key)
    
    return encrypted_dict

def write_json_file(json_dict : dict , path : str , ectype : str , key : str) -> None:
    if ectype == 'b4':
        if not key:
            raise ValueError(f"SHRJsonLoader [ERROR.1009] json file enkey not found. File Path : {path}")
        # 深拷贝原始字典，避免修改原始数据
        encrypted_dict = encrypt_dict_keys_and_values(deepcopy(json_dict), key)
        # 将加密后的字典写入文件
        with open(path , "w" , encoding = "utf-8") as f:
            json.dump(encrypted_dict , f , ensure_ascii = False)
            f.close()
    else:
        # 非加密类型，直接写入原始数据
        with open(path , "w" , encoding = "utf-8") as f:
            json.dump(json_dict , f , ensure_ascii = False)
            f.close()