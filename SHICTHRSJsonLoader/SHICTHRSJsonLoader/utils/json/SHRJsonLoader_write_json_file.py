
import json

def write_json_file(json_dict : dict , path : str) -> None:
    with open(path , "w" , encoding = "utf-8") as f:
        json.dump(json_dict , f , ensure_ascii = False)
        f.close()