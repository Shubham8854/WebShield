scan_results = {

    "target": "",

    "score": 0,

    "risk_level": "",

    "headers": {},

    "ssl": {},

    "whois": {},

    "dns": {},

    "technology": [],

    "ports": [],

    "findings": [],

    "open_ports": 0,

    "recommendations": []
}


def set_result(key, value):

    scan_results[key] = value


def get_results():

    return scan_results
