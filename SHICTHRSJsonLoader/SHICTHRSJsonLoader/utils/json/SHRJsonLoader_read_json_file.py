
import json
import base64
import hashlib
import hmac
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import unpad
from Crypto.Hash import Poly1305
from ..hash.SHRJsonLoader_en_md5_hexdigest import en_md5hash_code

def decrypt_with_key_b4(encrypted_data : str , key : str) -> str:
    if not key:
        return encrypted_data
    
    try:
        decoded_data = base64.b64decode(encrypted_data.encode('utf-8')).decode('utf-8')
        decrypted_data = []
        key_length = len(key)
        for i, char in enumerate(decoded_data):
            decrypted_char = chr(ord(char) ^ ord(key[i % key_length]))
            decrypted_data.append(decrypted_char)
        
        return ''.join(decrypted_data)
    except Exception:
        return encrypted_data

def decrypt_with_key_b0(encrypted_data : str , key : str) -> str:
    if not key:
        return encrypted_data
    
    try:
        key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
        data = base64.b64decode(encrypted_data)
        
        # 分离 nonce、密文和 MAC
        nonce = data[:12]
        mac = data[-16:]  # Poly1305 MAC 是 16 字节
        ciphertext = data[12:-16]
        
        # 验证 MAC
        mac_obj = Poly1305.new(key=key_bytes, cipher=ChaCha20, nonce=nonce).update(ciphertext)
        
        # 比较计算的 MAC 和存储的 MAC
        if not hmac.compare_digest(mac_obj.digest(), mac):
            return encrypted_data
            
        # 解密数据
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        
        return plaintext.decode('utf-8')
    except Exception:
        return encrypted_data

def decrypt_with_key_b1(encrypted_data : str , key : str) -> str:
    if not key:
        return encrypted_data
    
    try:
        key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
        data = base64.b64decode(encrypted_data)
        
        # 分离 nonce 和密文
        nonce = data[:12]
        ciphertext = data[12:]
        
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        
        return plaintext.decode('utf-8')
    except Exception:
        return encrypted_data

def decrypt_with_key_b2(encrypted_data : str , key : str) -> str:
    if not key:
        return encrypted_data
    
    try:
        key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
        data = base64.b64decode(encrypted_data)
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
        return encrypted_data

def decrypt_with_key_b3(encrypted_data : str , key : str) -> str:
    if not key:
        return encrypted_data
    
    try:
        key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
        combined = base64.b64decode(encrypted_data)
        
        # 分离数据和HMAC
        parts = combined.split(b'|')
        if len(parts) < 2:
            return encrypted_data
            
        data = parts[0]
        stored_hmac = base64.b64decode(parts[1])
        
        # 验证HMAC
        hmac_obj = hmac.new(key_bytes, data, hashlib.sha256)
        computed_hmac = hmac_obj.digest()
        
        if not hmac.compare_digest(stored_hmac, computed_hmac):
            return encrypted_data
            
        return data.decode('utf-8')
    except Exception:
        return encrypted_data

def decrypt_key_and_verify_hash_b4(encrypted_key_with_hash : str , key : str) -> str:
    try:
        parts = encrypted_key_with_hash.rsplit('_', 1)
        if len(parts) != 2:
            return encrypted_key_with_hash
        
        encrypted_key, hash_part = parts
        original_key = decrypt_with_key_b4(encrypted_key, key)
        expected_hash = en_md5hash_code(original_key)[:8]
        if expected_hash == hash_part:
            return original_key
        else:
            return encrypted_key_with_hash
    except Exception:
        return encrypted_key_with_hash

def decrypt_key_and_verify_hash_b0(encrypted_key_with_hash : str , key : str) -> str:
    try:
        parts = encrypted_key_with_hash.rsplit('_', 1)
        if len(parts) != 2:
            return encrypted_key_with_hash
        
        encrypted_key, hash_part = parts
        original_key = decrypt_with_key_b0(encrypted_key, key)
        expected_hash = en_md5hash_code(original_key)[:8]
        if expected_hash == hash_part:
            return original_key
        else:
            return encrypted_key_with_hash
    except Exception:
        return encrypted_key_with_hash

def decrypt_key_and_verify_hash_b1(encrypted_key_with_hash : str , key : str) -> str:
    try:
        parts = encrypted_key_with_hash.rsplit('_', 1)
        if len(parts) != 2:
            return encrypted_key_with_hash
        
        encrypted_key, hash_part = parts
        original_key = decrypt_with_key_b1(encrypted_key, key)
        expected_hash = en_md5hash_code(original_key)[:8]
        if expected_hash == hash_part:
            return original_key
        else:
            return encrypted_key_with_hash
    except Exception:
        return encrypted_key_with_hash

def decrypt_key_and_verify_hash_b2(encrypted_key_with_hash : str , key : str) -> str:
    try:
        parts = encrypted_key_with_hash.rsplit('_', 1)
        if len(parts) != 2:
            return encrypted_key_with_hash
        
        encrypted_key, hash_part = parts
        original_key = decrypt_with_key_b2(encrypted_key, key)
        expected_hash = en_md5hash_code(original_key)[:8]
        if expected_hash == hash_part:
            return original_key
        else:
            return encrypted_key_with_hash
    except Exception:
        return encrypted_key_with_hash

def decrypt_key_and_verify_hash_b3(encrypted_key_with_hash : str , key : str) -> str:
    try:
        parts = encrypted_key_with_hash.rsplit('_', 1)
        if len(parts) != 2:
            return encrypted_key_with_hash
        
        encrypted_key, hash_part = parts
        original_key = decrypt_with_key_b3(encrypted_key, key)
        expected_hash = en_md5hash_code(original_key)[:8]
        if expected_hash == hash_part:
            return original_key
        else:
            return encrypted_key_with_hash
    except Exception:
        return encrypted_key_with_hash

def decrypt_dict_keys_and_values_b4(encrypted_dict : dict , key : str) -> dict:
    decrypted_dict = {}
    for encrypted_key_name, value in encrypted_dict.items():
        original_key = decrypt_key_and_verify_hash_b4(encrypted_key_name, key)
        
        if isinstance(value, dict):
            decrypted_dict[original_key] = decrypt_dict_keys_and_values_b4(value, key)
        elif isinstance(value, (list, tuple)):
            decrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    decrypted_list.append(decrypt_dict_keys_and_values_b4(item, key))
                elif isinstance(item, str):
                    decrypted_list.append(decrypt_with_key_b4(item, key))
                else:
                    decrypted_list.append(item)
            decrypted_dict[original_key] = decrypted_list
        elif isinstance(value, str):
            decrypted_dict[original_key] = decrypt_with_key_b4(value, key)
        else:
            decrypted_dict[original_key] = value
    
    return decrypted_dict

def decrypt_dict_keys_and_values_b0(encrypted_dict : dict , key : str) -> dict:
    decrypted_dict = {}
    for encrypted_key_name, value in encrypted_dict.items():
        original_key = decrypt_key_and_verify_hash_b0(encrypted_key_name, key)
        
        if isinstance(value, dict):
            decrypted_dict[original_key] = decrypt_dict_keys_and_values_b0(value, key)
        elif isinstance(value, (list, tuple)):
            decrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    decrypted_list.append(decrypt_dict_keys_and_values_b0(item, key))
                elif isinstance(item, str):
                    decrypted_list.append(decrypt_with_key_b0(item, key))
                else:
                    decrypted_list.append(item)
            decrypted_dict[original_key] = decrypted_list
        elif isinstance(value, str):
            decrypted_dict[original_key] = decrypt_with_key_b0(value, key)
        else:
            decrypted_dict[original_key] = value
    
    return decrypted_dict

def decrypt_dict_keys_and_values_b1(encrypted_dict : dict , key : str) -> dict:
    decrypted_dict = {}
    for encrypted_key_name, value in encrypted_dict.items():
        original_key = decrypt_key_and_verify_hash_b1(encrypted_key_name, key)
        
        if isinstance(value, dict):
            decrypted_dict[original_key] = decrypt_dict_keys_and_values_b1(value, key)
        elif isinstance(value, (list, tuple)):
            decrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    decrypted_list.append(decrypt_dict_keys_and_values_b1(item, key))
                elif isinstance(item, str):
                    decrypted_list.append(decrypt_with_key_b1(item, key))
                else:
                    decrypted_list.append(item)
            decrypted_dict[original_key] = decrypted_list
        elif isinstance(value, str):
            decrypted_dict[original_key] = decrypt_with_key_b1(value, key)
        else:
            decrypted_dict[original_key] = value
    
    return decrypted_dict

def decrypt_dict_keys_and_values_b2(encrypted_dict : dict , key : str) -> dict:
    decrypted_dict = {}
    for encrypted_key_name, value in encrypted_dict.items():
        original_key = decrypt_key_and_verify_hash_b2(encrypted_key_name, key)
        
        if isinstance(value, dict):
            decrypted_dict[original_key] = decrypt_dict_keys_and_values_b2(value, key)
        elif isinstance(value, (list, tuple)):
            decrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    decrypted_list.append(decrypt_dict_keys_and_values_b2(item, key))
                elif isinstance(item, str):
                    decrypted_list.append(decrypt_with_key_b2(item, key))
                else:
                    decrypted_list.append(item)
            decrypted_dict[original_key] = decrypted_list
        elif isinstance(value, str):
            decrypted_dict[original_key] = decrypt_with_key_b2(value, key)
        else:
            decrypted_dict[original_key] = value
    
    return decrypted_dict

def decrypt_dict_keys_and_values_b3(encrypted_dict : dict , key : str) -> dict:
    decrypted_dict = {}
    for encrypted_key_name, value in encrypted_dict.items():
        original_key = decrypt_key_and_verify_hash_b3(encrypted_key_name, key)
        
        if isinstance(value, dict):
            decrypted_dict[original_key] = decrypt_dict_keys_and_values_b3(value, key)
        elif isinstance(value, (list, tuple)):
            decrypted_list = []
            for item in value:
                if isinstance(item, dict):
                    decrypted_list.append(decrypt_dict_keys_and_values_b3(item, key))
                elif isinstance(item, str):
                    decrypted_list.append(decrypt_with_key_b3(item, key))
                else:
                    decrypted_list.append(item)
            decrypted_dict[original_key] = decrypted_list
        elif isinstance(value, str):
            decrypted_dict[original_key] = decrypt_with_key_b3(value, key)
        else:
            decrypted_dict[original_key] = value
    
    return decrypted_dict

def read_json_file(path : str , ectype : str , key : str , verify : bool = False) -> dict:
    with open(path , "r" , encoding = "utf-8") as f:
        data = json.load(f)
        f.close()
    
    if ectype is None or ectype == '':
        stored_ectype = data.get("_SHR_ECTYPE", None)
        if stored_ectype is not None and stored_ectype != '' and stored_ectype != ectype:
            raise ValueError(f"SHRJsonLoader [ERROR.1014] encryption type mismatch. File was encrypted with '{stored_ectype}' but '{ectype}' was provided. File Path : {path}")
        
        data_without_metadata = {k: v for k, v in data.items() if k != "_SHR_ECTYPE"}
        return data_without_metadata
    else:
        # 首先获取存储的加密类型
        stored_ectype = data.get("_SHR_ECTYPE", None)
        
        # 如果提供的 ectype 为空，使用文件中存储的加密类型
        if ectype is None or ectype == '':
            ectype = stored_ectype
        elif stored_ectype and stored_ectype != ectype:
            raise ValueError(f"SHRJsonLoader [ERROR.1014] encryption type mismatch. File was encrypted with '{stored_ectype}' but '{ectype}' was provided. File Path : {path}")
        
        if ectype == 'b0':
            if not key:
                raise ValueError(f"SHRJsonLoader [ERROR.1009] json file enkey not found. File Path : {path}")
            
            # 优先检查文件哈希值（在解密前）
            has_file_hash = "_SHR_FILE_HASH" in data
            encrypted_file_hash = data.get("_SHR_FILE_HASH", None)
            
            if has_file_hash and encrypted_file_hash:
                # 创建当前数据的副本（不包含文件哈希值）
                temp_data = {k: v for k, v in data.items() if k != "_SHR_FILE_HASH"}
                
                # 计算当前数据的哈希值
                temp_data_str = json.dumps(temp_data, sort_keys=True, ensure_ascii=False)
                current_file_hash = en_md5hash_code(temp_data_str)
                
                # 解密原始文件哈希值
                original_file_hash = decrypt_with_key_b0(encrypted_file_hash, key)
                
                if current_file_hash != original_file_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1016] file integrity check failed. File may have been tampered with. File Path : {path}")
            
            # 验证加密文件有效性
            if "_SHR_VERIFICATION" not in data:
                raise ValueError(f"SHRJsonLoader [ERROR.1010] invalid encrypted file. File Path : {path}")
            
            verification_token = data["_SHR_VERIFICATION"]
            decrypted_token = decrypt_with_key_b0(verification_token, key)
            
            if decrypted_token != key:
                raise ValueError(f"SHRJsonLoader [ERROR.1011] incorrect key provided. File Path : {path}")
            
            has_data_hash = "_SHR_DATA_HASH" in data
            encrypted_data_hash = data.get("_SHR_DATA_HASH", None)
            
            data_without_verification = {k: v for k, v in data.items() if k not in ["_SHR_ECTYPE", "_SHR_VERIFICATION", "_SHR_DATA_HASH", "_SHR_FILE_HASH"]}
            
            decrypted_data = decrypt_dict_keys_and_values_b0(data_without_verification, key)
            
            # 验证数据哈希值
            if verify and has_data_hash and encrypted_data_hash:
                decrypted_data_str = json.dumps(decrypted_data, sort_keys=True, ensure_ascii=False)
                current_data_hash = en_md5hash_code(decrypted_data_str)
                original_hash = decrypt_with_key_b0(encrypted_data_hash, key)
                
                if current_data_hash != original_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1012] data integrity check failed. File may have been tampered with. File Path : {path}")
            
            return decrypted_data
        elif ectype == 'b1':
            if not key:
                raise ValueError(f"SHRJsonLoader [ERROR.1009] json file enkey not found. File Path : {path}")
            
            # 优先检查文件哈希值（在解密前）
            has_file_hash = "_SHR_FILE_HASH" in data
            encrypted_file_hash = data.get("_SHR_FILE_HASH", None)
            
            if has_file_hash and encrypted_file_hash:
                # 创建当前数据的副本（不包含文件哈希值）
                temp_data = {k: v for k, v in data.items() if k != "_SHR_FILE_HASH"}
                
                # 计算当前数据的哈希值
                temp_data_str = json.dumps(temp_data, sort_keys=True, ensure_ascii=False)
                current_file_hash = en_md5hash_code(temp_data_str)
                
                # 解密原始文件哈希值
                original_file_hash = decrypt_with_key_b1(encrypted_file_hash, key)
                
                if current_file_hash != original_file_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1016] file integrity check failed. File may have been tampered with. File Path : {path}")
            
            # 验证加密文件有效性
            if "_SHR_VERIFICATION" not in data:
                raise ValueError(f"SHRJsonLoader [ERROR.1010] invalid encrypted file. File Path : {path}")
            
            verification_token = data["_SHR_VERIFICATION"]
            decrypted_token = decrypt_with_key_b1(verification_token, key)
            
            if decrypted_token != key:
                raise ValueError(f"SHRJsonLoader [ERROR.1011] incorrect key provided. File Path : {path}")
            
            has_data_hash = "_SHR_DATA_HASH" in data
            encrypted_data_hash = data.get("_SHR_DATA_HASH", None)
            
            data_without_verification = {k: v for k, v in data.items() if k not in ["_SHR_ECTYPE", "_SHR_VERIFICATION", "_SHR_DATA_HASH", "_SHR_FILE_HASH"]}
            
            decrypted_data = decrypt_dict_keys_and_values_b1(data_without_verification, key)
            
            # 验证数据哈希值
            if verify and has_data_hash and encrypted_data_hash:
                decrypted_data_str = json.dumps(decrypted_data, sort_keys=True, ensure_ascii=False)
                current_data_hash = en_md5hash_code(decrypted_data_str)
                original_hash = decrypt_with_key_b1(encrypted_data_hash, key)
                
                if current_data_hash != original_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1012] data integrity check failed. File may have been tampered with. File Path : {path}")
            
            return decrypted_data
        elif ectype == 'b2':
            if not key:
                raise ValueError(f"SHRJsonLoader [ERROR.1009] json file enkey not found. File Path : {path}")
            
            # 优先检查文件哈希值（在解密前）
            has_file_hash = "_SHR_FILE_HASH" in data
            encrypted_file_hash = data.get("_SHR_FILE_HASH", None)
            
            if has_file_hash and encrypted_file_hash:
                # 创建当前数据的副本（不包含文件哈希值）
                temp_data = {k: v for k, v in data.items() if k != "_SHR_FILE_HASH"}
                
                # 计算当前数据的哈希值
                temp_data_str = json.dumps(temp_data, sort_keys=True, ensure_ascii=False)
                current_file_hash = en_md5hash_code(temp_data_str)
                
                # 解密原始文件哈希值
                original_file_hash = decrypt_with_key_b2(encrypted_file_hash, key)
                
                if current_file_hash != original_file_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1016] file integrity check failed. File may have been tampered with. File Path : {path}")
            
            # 验证加密文件有效性
            if "_SHR_VERIFICATION" not in data:
                raise ValueError(f"SHRJsonLoader [ERROR.1010] invalid encrypted file. File Path : {path}")
            
            verification_token = data["_SHR_VERIFICATION"]
            decrypted_token = decrypt_with_key_b2(verification_token, key)
            
            if decrypted_token != key:
                raise ValueError(f"SHRJsonLoader [ERROR.1011] incorrect key provided. File Path : {path}")
            
            has_data_hash = "_SHR_DATA_HASH" in data
            encrypted_data_hash = data.get("_SHR_DATA_HASH", None)
            
            data_without_verification = {k: v for k, v in data.items() if k not in ["_SHR_ECTYPE", "_SHR_VERIFICATION", "_SHR_DATA_HASH", "_SHR_FILE_HASH"]}
            
            decrypted_data = decrypt_dict_keys_and_values_b2(data_without_verification, key)
            
            # 验证数据哈希值
            if verify and has_data_hash and encrypted_data_hash:
                decrypted_data_str = json.dumps(decrypted_data, sort_keys=True, ensure_ascii=False)
                current_data_hash = en_md5hash_code(decrypted_data_str)
                original_hash = decrypt_with_key_b2(encrypted_data_hash, key)
                
                if current_data_hash != original_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1012] data integrity check failed. File may have been tampered with. File Path : {path}")
            
            return decrypted_data
        elif ectype == 'b3':
            if not key:
                raise ValueError(f"SHRJsonLoader [ERROR.1009] json file enkey not found. File Path : {path}")
            
            # 优先检查文件哈希值（在解密前）
            has_file_hash = "_SHR_FILE_HASH" in data
            encrypted_file_hash = data.get("_SHR_FILE_HASH", None)
            
            if has_file_hash and encrypted_file_hash:
                # 创建当前数据的副本（不包含文件哈希值）
                temp_data = {k: v for k, v in data.items() if k != "_SHR_FILE_HASH"}
                
                # 计算当前数据的哈希值
                temp_data_str = json.dumps(temp_data, sort_keys=True, ensure_ascii=False)
                current_file_hash = en_md5hash_code(temp_data_str)
                
                # 解密原始文件哈希值
                original_file_hash = decrypt_with_key_b3(encrypted_file_hash, key)
                
                if current_file_hash != original_file_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1016] file integrity check failed. File may have been tampered with. File Path : {path}")
            
            # 验证加密文件有效性
            if "_SHR_VERIFICATION" not in data:
                raise ValueError(f"SHRJsonLoader [ERROR.1010] invalid encrypted file. File Path : {path}")
            
            verification_token = data["_SHR_VERIFICATION"]
            decrypted_token = decrypt_with_key_b3(verification_token, key)
            
            if decrypted_token != key:
                raise ValueError(f"SHRJsonLoader [ERROR.1011] incorrect key provided. File Path : {path}")
            
            has_data_hash = "_SHR_DATA_HASH" in data
            encrypted_data_hash = data.get("_SHR_DATA_HASH", None)
            
            data_without_verification = {k: v for k, v in data.items() if k not in ["_SHR_ECTYPE", "_SHR_VERIFICATION", "_SHR_DATA_HASH", "_SHR_FILE_HASH"]}
            
            decrypted_data = decrypt_dict_keys_and_values_b3(data_without_verification, key)
            
            # 验证数据哈希值
            if verify and has_data_hash and encrypted_data_hash:
                decrypted_data_str = json.dumps(decrypted_data, sort_keys=True, ensure_ascii=False)
                current_data_hash = en_md5hash_code(decrypted_data_str)
                original_hash = decrypt_with_key_b3(encrypted_data_hash, key)
                
                if current_data_hash != original_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1012] data integrity check failed. File may have been tampered with. File Path : {path}")
            
            return decrypted_data
        elif ectype == 'b4':
            if not key:
                raise ValueError(f"SHRJsonLoader [ERROR.1009] json file enkey not found. File Path : {path}")
            
            # 优先检查文件哈希值（在解密前）
            has_file_hash = "_SHR_FILE_HASH" in data
            encrypted_file_hash = data.get("_SHR_FILE_HASH", None)
            
            if has_file_hash and encrypted_file_hash:
                # 创建当前数据的副本（不包含文件哈希值）
                temp_data = {k: v for k, v in data.items() if k != "_SHR_FILE_HASH"}
                
                # 计算当前数据的哈希值
                temp_data_str = json.dumps(temp_data, sort_keys=True, ensure_ascii=False)
                current_file_hash = en_md5hash_code(temp_data_str)
                
                # 解密原始文件哈希值
                original_file_hash = decrypt_with_key_b4(encrypted_file_hash, key)
                
                if current_file_hash != original_file_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1016] file integrity check failed. File may have been tampered with. File Path : {path}")
            
            # 验证加密文件有效性
            if "_SHR_VERIFICATION" not in data:
                raise ValueError(f"SHRJsonLoader [ERROR.1010] invalid encrypted file. File Path : {path}")
            
            verification_token = data["_SHR_VERIFICATION"]
            decrypted_token = decrypt_with_key_b4(verification_token, key)
            
            if decrypted_token != key:
                raise ValueError(f"SHRJsonLoader [ERROR.1011] incorrect key provided. File Path : {path}")
            
            has_data_hash = "_SHR_DATA_HASH" in data
            encrypted_data_hash = data.get("_SHR_DATA_HASH", None)
            
            data_without_verification = {k: v for k, v in data.items() if k not in ["_SHR_ECTYPE", "_SHR_VERIFICATION", "_SHR_DATA_HASH", "_SHR_FILE_HASH"]}
            
            decrypted_data = decrypt_dict_keys_and_values_b4(data_without_verification, key)
            
            # 验证数据哈希值
            if verify and has_data_hash and encrypted_data_hash:
                decrypted_data_str = json.dumps(decrypted_data, sort_keys=True, ensure_ascii=False)
                current_data_hash = en_md5hash_code(decrypted_data_str)
                original_hash = decrypt_with_key_b4(encrypted_data_hash, key)
                
                if current_data_hash != original_hash:
                    raise ValueError(f"SHRJsonLoader [ERROR.1012] data integrity check failed. File may have been tampered with. File Path : {path}")
            
            return decrypted_data
        else:
            raise ValueError(f"SHRJsonLoader [ERROR.1013] unsupported encryption type: {ectype}. Supported types: 'b0', 'b1', 'b2', 'b3', 'b4' or None")