
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

def read_json_file(path : str , ectype : str , key : str , verify : bool = False) -> dict:
    with open(path , "r" , encoding = "utf-8") as f:
        data = json.load(f)
        f.close()
    
    if ectype is None or ectype == '':
        # 非加密类型，直接返回原始数据
        return data
    elif ectype == 'b4':
        if not key:
            raise ValueError(f"SHRJsonLoader [ERROR.1009] json file enkey not found. File Path : {path}")
        
        # 验证密钥是否正确
        if "_SHR_VERIFICATION" not in data:
            raise ValueError(f"SHRJsonLoader [ERROR.1010] invalid encrypted file. File Path : {path}")
        
        # 解密验证令牌
        verification_token = data["_SHR_VERIFICATION"]
        decrypted_token = decrypt_with_key(verification_token, key)
        
        # 检查验证令牌是否与密钥匹配
        if decrypted_token != key:
            raise ValueError(f"SHRJsonLoader [ERROR.1011] incorrect key provided. File Path : {path}")
        
        # 检查是否需要验证数据完整性
        has_data_hash = "_SHR_DATA_HASH" in data
        encrypted_data_hash = data.get("_SHR_DATA_HASH", None)
        
        # 创建不包含验证令牌和哈希值的数据副本
        data_without_verification = {k: v for k, v in data.items() if k not in ["_SHR_VERIFICATION", "_SHR_DATA_HASH"]}
        
        # 解密数据
        decrypted_data = decrypt_dict_keys_and_values(data_without_verification, key)
        
        # 如果verify为True且存在哈希值，验证数据完整性
        if verify and has_data_hash and encrypted_data_hash:
            # 计算解密后数据的哈希值
            decrypted_data_str = json.dumps(decrypted_data, sort_keys=True, ensure_ascii=False)
            current_data_hash = en_md5hash_code(decrypted_data_str)
            
            # 解密原始哈希值
            original_hash = decrypt_with_key(encrypted_data_hash, key)
            
            # 比较哈希值
            if current_data_hash != original_hash:
                raise ValueError(f"SHRJsonLoader [ERROR.1012] data integrity check failed. File may have been tampered with. File Path : {path}")
        
        return decrypted_data
    else:
        # 不支持的加密类型，抛出异常
        raise ValueError(f"SHRJsonLoader [ERROR.1013] unsupported encryption type: {ectype}. Supported types: 'b4' or None")