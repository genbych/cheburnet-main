import requests


def get(url: str, params = None, **kwargs):
    r = requests.get(url, params, **kwargs)

    return r.json()

def post(url: str, data = None, json = None, **kwargs):
    r = requests.post(url, data, json, **kwargs)

    return r.json()


