
import json
import base64
from copy import deepcopy

def decrypt_with_key(encrypted_data : str , key : str) -> str:
    """使用密钥对数据进行解密
    Args:
        encrypted_data: 加密的base64字符串
        key: 解密密钥
    Returns:
        解密后的原始数据
    """
    if not key:
        return encrypted_data
    
    try:
        # 先进行base64解码
        decoded_data = base64.b64decode(encrypted_data.encode('utf-8')).decode('utf-8')
        # 然后进行异或解密
        decrypted_data = []
        key_length = len(key)
        for i, char in enumerate(decoded_data):
            decrypted_char = chr(ord(char) ^ ord(key[i % key_length]))
            decrypted_data.append(decrypted_char)
        
        return ''.join(decrypted_data)
    except Exception:
        # 如果解密失败，返回原始数据
        return encrypted_data

def decrypt_dict_values(encrypted_dict : dict , key : str) -> dict:
    """递归地对字典中的所有值进行解密
    Args:
        encrypted_dict: 要解密的字典
        key: 解密密钥
    Returns:
        解密后的字典
    """
    decrypted_dict = {}
    for key_name, value in encrypted_dict.items():
        if isinstance(value, dict):
            # 如果值是字典，递归处理
            decrypted_dict[key_name] = decrypt_dict_values(value, key)
        elif isinstance(value, (list, tuple)):
            # 如果值是列表或元组，处理每个元素
            decrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    decrypted_list.append(decrypt_dict_values(item, key))
                elif isinstance(item, str):
                    decrypted_list.append(decrypt_with_key(item, key))
                else:
                    decrypted_list.append(item)
            decrypted_dict[key_name] = decrypted_list
        elif isinstance(value, str):
            # 字符串值直接解密
            decrypted_dict[key_name] = decrypt_with_key(value, key)
        else:
            # 非字符串类型直接返回
            decrypted_dict[key_name] = value
    
    return decrypted_dict

def read_json_file(path : str , ectype : str , key : str) -> dict:
    with open(path , "r" , encoding = "utf-8") as f:
        data = json.load(f)
        f.close()
    
    if ectype == 'b4':
        if not key:
            raise ValueError(f"SHRJsonLoader [ERROR.1009] json file enkey not found. File Path : {path}")
        # 解密数据
        return decrypt_dict_values(data, key)
    else:
        # 非加密类型，直接返回原始数据
        return data