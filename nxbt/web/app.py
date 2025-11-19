import json
import os
from threading import RLock
import time
from socket import gethostname

from .cert import generate_cert
from ..nxbt import Nxbt, PRO_CONTROLLER
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import eventlet

app = Flask(__name__,
            static_url_path='',
            static_folder='static',)
nxbt = Nxbt()

# Configuring/retrieving secret key
secrets_path = os.path.join(
    os.path.dirname(__file__), "secrets.txt"
)
if not os.path.isfile(secrets_path):
    secret_key = os.urandom(24).hex()
    with open(secrets_path, "w") as f:
        f.write(secret_key)
else:
    secret_key = None
    with open(secrets_path, "r") as f:
        secret_key = f.read()
app.config['SECRET_KEY'] = secret_key

# Starting socket server with Flask app
sio = SocketIO(app, cookie=False)

user_info_lock = RLock()
USER_INFO = {}
PRESETS_LOCK = RLock()
PRESETS_DIR = os.path.join(os.path.dirname(__file__), 'presets')
if not os.path.isdir(PRESETS_DIR):
    try:
        os.makedirs(PRESETS_DIR, exist_ok=True)
    except Exception:
        pass

def _get_global_presets_path():
    return os.path.join(PRESETS_DIR, 'presets_global.json')

def _read_global_presets():
    path = _get_global_presets_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _write_global_presets(presets):
    path = _get_global_presets_path()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(presets, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@sio.on('connect')
def on_connect():
    with user_info_lock:
        USER_INFO[request.sid] = {}

@sio.on('state')
def on_state():
    state_proxy = nxbt.state.copy()
    state = {}
    for controller in state_proxy.keys():
        state[controller] = state_proxy[controller].copy()
    emit('state', state)

@sio.on('disconnect')
def on_disconnect():
    print("Disconnected")
    with user_info_lock:
        try:
            index = USER_INFO[request.sid]["controller_index"]
            nxbt.remove_controller(index)
        except KeyError:
            pass

@sio.on('shutdown')
def on_shutdown(index):
    nxbt.remove_controller(index)

@sio.on('web_create_pro_controller')
def on_create_controller():
    print("Create Controller")

    try:
        reconnect_addresses = nxbt.get_switch_addresses()
        index = nxbt.create_controller(PRO_CONTROLLER, reconnect_address=reconnect_addresses)

        with user_info_lock:
            USER_INFO[request.sid]["controller_index"] = index

        emit('create_pro_controller', index)
    except Exception as e:
        emit('error', str(e))

@sio.on('input')
def handle_input(message):
    # print("Webapp Input", time.perf_counter())
    message = json.loads(message)
    index = message[0]
    input_packet = message[1]
    nxbt.set_controller_input(index, input_packet)

@sio.on('macro')
def handle_macro(message):
    message = json.loads(message)
    index = message[0]
    macro = message[1]
    try:
        # Run macro asynchronously and return macro_id to client
        macro_id = nxbt.macro(index, macro, block=False)
        # Notify the originating client which macro_id was started
        emit('macro_started', json.dumps([index, macro_id]))
    except Exception as e:
        emit('error', str(e))


@sio.on('stop_macro')
def handle_stop_macro(message):
    try:
        data = json.loads(message)
        index = data[0]
        macro_id = data[1]
        nxbt.stop_macro(index, macro_id, block=False)
        emit('macro_stopped', json.dumps([index, macro_id]))
    except Exception as e:
        emit('error', str(e))


@sio.on('clear_macros')
def handle_clear_macros(message):
    try:
        # message may be raw index or JSON; try to parse
        try:
            index = json.loads(message)
        except Exception:
            index = message
        nxbt.clear_macros(index)
        emit('macros_cleared', index)
    except Exception as e:
        emit('error', str(e))

@app.route('/api/presets', methods=['GET'])
def api_get_global_presets():
    with PRESETS_LOCK:
        presets = _read_global_presets()
    return jsonify({'presets': presets})

@app.route('/api/presets/<name>', methods=['POST'])
def api_save_global_preset(name):
    data = {}
    try:
        data = request.get_json(force=True)
    except Exception:
        pass
    macro = data.get('macro', '') if isinstance(data, dict) else ''
    with PRESETS_LOCK:
        presets = _read_global_presets()
        presets[name] = macro
        success = _write_global_presets(presets)
    if not success:
        return jsonify({'error': 'failed to write global presets'}), 500
    return ('', 204)

@app.route('/api/presets/<name>', methods=['DELETE'])
def api_delete_global_preset(name):
    with PRESETS_LOCK:
        presets = _read_global_presets()
        if name in presets:
            del presets[name]
            _write_global_presets(presets)
    return ('', 204)

def start_web_app(ip='0.0.0.0', port=8000, usessl=False, cert_path=None):
    if usessl:
        if cert_path is None:
            # Store certs in the package directory
            cert_path = os.path.join(
                os.path.dirname(__file__), "cert.pem"
            )
            key_path = os.path.join(
                os.path.dirname(__file__), "key.pem"
            )
        else:
            # If specified, store certs at the user's preferred location
            cert_path = os.path.join(
                cert_path, "cert.pem"
            )
            key_path = os.path.join(
                cert_path, "key.pem"
            )
        if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
            print(
                "\n"
                "-----------------------------------------\n"
                "---------------->WARNING<----------------\n"
                "The NXBT webapp is being run with self-\n"
                "signed SSL certificates for use on your\n"
                "local network.\n"
                "\n"
                "These certificates ARE NOT safe for\n"
                "production use. Please generate valid\n"
                "SSL certificates if you plan on using the\n"
                "NXBT webapp anywhere other than your own\n"
                "network.\n"
                "-----------------------------------------\n"
                "\n"
                "The above warning will only be shown once\n"
                "on certificate generation."
                "\n"
            )
            print("Generating certificates...")
            cert, key = generate_cert(gethostname())
            with open(cert_path, "wb") as f:
                f.write(cert)
            with open(key_path, "wb") as f:
                f.write(key)

        eventlet.wsgi.server(eventlet.wrap_ssl(eventlet.listen((ip, port)),
            certfile=cert_path, keyfile=key_path), app)
    else:
        eventlet.wsgi.server(eventlet.listen((ip, port)), app)

if __name__ == "__main__":
    start_web_app()
