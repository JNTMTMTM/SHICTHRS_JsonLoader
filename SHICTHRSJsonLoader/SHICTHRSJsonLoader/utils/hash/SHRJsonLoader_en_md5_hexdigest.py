
import hashlib

def en_md5hash_code(decy_code : str) -> str:
    md5 = hashlib.md5()
    md5.update(decy_code.encode('utf-8'))
    ecy_code = md5.hexdigest()
    return ecy_code
