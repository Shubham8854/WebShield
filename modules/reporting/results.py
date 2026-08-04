scan_results = {

    "target": "",

    "score": 0,

    "rating": "",

    "headers": {},

    "ssl": {},

    "whois": {},

    "dns": {},

    "technology": [],

    "ports": []

}


def set_result(key, value):

    scan_results[key] = value


def get_results():

    return scan_results
