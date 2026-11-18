"""Session cookies. Deliberately vulnerable: unpickles client-supplied
bytes (CWE-502)."""
import base64
import pickle


def dump_session(data):
    return base64.b64encode(pickle.dumps(data)).decode()


def load_session(cookie):
    data = pickle.loads(base64.b64decode(cookie))
    return data
