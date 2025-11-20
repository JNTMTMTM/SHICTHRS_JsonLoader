
import base64

def en_base64_code(decy_code : str) -> str:
    return base64.b64encode(decy_code.encode('utf-8')).decode('utf-8')