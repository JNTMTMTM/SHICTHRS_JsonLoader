
import base64

def de_base64_code(ecy_code : str) -> str:
    return base64.b64decode(ecy_code).decode('utf-8')