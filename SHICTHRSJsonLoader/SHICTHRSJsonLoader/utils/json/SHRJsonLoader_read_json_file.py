
import json
import base64
from ..hash.SHRJsonLoader_en_md5_hexdigest import en_md5hash_code

def decrypt_with_key(encrypted_data : str , key : str) -> str:
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

def decrypt_key_and_verify_hash(encrypted_key_with_hash : str , key : str) -> str:
    try:
        # 分离加密的键和哈希值
        parts = encrypted_key_with_hash.rsplit('_', 1)
        if len(parts) != 2:
            # 如果格式不正确，直接返回原始键
            return encrypted_key_with_hash
        
        encrypted_key, hash_part = parts
        
        # 解密键
        original_key = decrypt_with_key(encrypted_key, key)
        
        # 验证哈希值
        expected_hash = en_md5hash_code(original_key)[:8]
        if expected_hash == hash_part:
            return original_key
        else:
            # 哈希值不匹配，返回原始键
            return encrypted_key_with_hash
    except Exception:
        # 解密失败，返回原始键
        return encrypted_key_with_hash

def decrypt_dict_keys_and_values(encrypted_dict : dict , key : str) -> dict:
    decrypted_dict = {}
    for encrypted_key_name, value in encrypted_dict.items():
        # 解密键并验证哈希值
        original_key = decrypt_key_and_verify_hash(encrypted_key_name, key)
        
        if isinstance(value, dict):
            # 如果值是字典，递归处理
            decrypted_dict[original_key] = decrypt_dict_keys_and_values(value, key)
        elif isinstance(value, (list, tuple)):
            # 如果值是列表或元组，处理每个元素
            decrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    decrypted_list.append(decrypt_dict_keys_and_values(item, key))
                elif isinstance(item, str):
                    decrypted_list.append(decrypt_with_key(item, key))
                else:
                    decrypted_list.append(item)
            decrypted_dict[original_key] = decrypted_list
        elif isinstance(value, str):
            # 字符串值直接解密
            decrypted_dict[original_key] = decrypt_with_key(value, key)
        else:
            # 非字符串类型直接返回
            decrypted_dict[original_key] = value
    
    return decrypted_dict

def read_json_file(path : str , ectype : str , key : str) -> dict:
    with open(path , "r" , encoding = "utf-8") as f:
        data = json.load(f)
        f.close()
    
    if ectype == 'b4':
        if not key:
            raise ValueError(f"SHRJsonLoader [ERROR.1009] json file enkey not found. File Path : {path}")
        # 解密数据
        return decrypt_dict_keys_and_values(data, key)
    else:
        # 非加密类型，直接返回原始数据
        return data