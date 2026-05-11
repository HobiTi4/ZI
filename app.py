import os
import time
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

from labs.lab1 import run_lab1_algorithm
from labs.lab2 import MD5
from labs.lab3 import rc5_cbc_pad_encrypt, rc5_cbc_pad_decrypt
from labs.lab4 import generate_rsa_keys, rsa_encrypt_data, rsa_decrypt_data
from labs.lab5 import generate_dsa_keys, dsa_sign, dsa_verify

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

RESULTS_FILE = 'results.txt'
LAB5_TEMPLATE = 'lab5.html'


def _write_results_file(content):
    with open(RESULTS_FILE, 'w') as file_handle:
        file_handle.write(content)


def _handle_lab3_post(action, file_storage, password):
    if not file_storage or file_storage.filename == '' or not password:
        return None

    original_filename = secure_filename(file_storage.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
    file_storage.save(filepath)
    try:
        if action == 'encrypt':
            output_filename = f"{original_filename}.enc"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            rc5_cbc_pad_encrypt(filepath, output_path, password, 16, 8, 16)
            return {'type': 'Encryption', 'input': original_filename, 'output': output_filename}

        if action == 'decrypt':
            output_filename = original_filename[:-4] if original_filename.endswith('.enc') else f"dec_{original_filename}"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            try:
                rc5_cbc_pad_decrypt(filepath, output_path, password, 16, 8, 16)
                return {'type': 'Decryption', 'input': original_filename, 'output': output_filename, 'success': True}
            except Exception as e:
                return {'type': 'Decryption', 'input': original_filename, 'success': False, 'error': str(e)}

        return None
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


def _handle_lab4_generate_keys():
    priv_pem, pub_pem = generate_rsa_keys(key_size=2048)
    return {
        'type': 'KeyGen',
        'message': 'RSA Keys generated successfully. Please download them now. The server does NOT store them.',
        'pub_pem': pub_pem.decode('utf-8'),
        'priv_pem': priv_pem.decode('utf-8')
    }


def _handle_lab4_encrypt(original_filename, filepath, file_data, key_data):
    start_rsa = time.time()
    encrypted_data = rsa_encrypt_data(file_data, key_data)
    rsa_time = time.time() - start_rsa

    output_filename = f"{original_filename}.rsa.enc"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    with open(output_path, 'wb') as file_handle:
        file_handle.write(encrypted_data)

    rc5_output = os.path.join(app.config['UPLOAD_FOLDER'], f"{original_filename}.rc5.enc")
    start_rc5 = time.time()
    rc5_cbc_pad_encrypt(filepath, rc5_output, 'benchmark_password', 16, 8, 17)
    rc5_time = time.time() - start_rc5

    if os.path.exists(rc5_output):
        os.remove(rc5_output)

    return {
        'type': 'Encryption',
        'input': original_filename,
        'output': output_filename,
        'rsa_time': round(rsa_time, 4),
        'rc5_time': round(rc5_time, 4)
    }


def _handle_lab4_decrypt(original_filename, file_data, key_data):
    decrypted_data = rsa_decrypt_data(file_data, key_data)
    output_filename = original_filename.replace('.rsa.enc', '') if '.rsa.enc' in original_filename else f"dec_{original_filename}"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    with open(output_path, 'wb') as file_handle:
        file_handle.write(decrypted_data)

    return {
        'type': 'Decryption',
        'input': original_filename,
        'output': output_filename,
        'success': True
    }


def _handle_lab4_post(action, data_file, key_file):
    if not data_file or data_file.filename == '':
        return {'error': 'Please select a data file to process.'}

    if not key_file or key_file.filename == '':
        return {'error': 'Please select the appropriate .pem key file.'}

    original_filename = secure_filename(data_file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
    data_file.save(filepath)
    try:
        with open(filepath, 'rb') as file_handle:
            file_data = file_handle.read()

        key_data = key_file.read()

        if action == 'encrypt':
            try:
                return _handle_lab4_encrypt(original_filename, filepath, file_data, key_data)
            except Exception as e:
                return {'error': f'Encryption failed. Ensure you uploaded a valid Public Key. Details: {str(e)}'}

        if action == 'decrypt':
            try:
                return _handle_lab4_decrypt(original_filename, file_data, key_data)
            except Exception as e:
                return {
                    'type': 'Decryption',
                    'input': original_filename,
                    'success': False,
                    'error': f'Decryption failed. Ensure you uploaded the correct Private Key or the file is corrupted. Details: {str(e)}'
                }

        return None
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


def _handle_lab5_generate_keys():
    priv_pem, pub_pem = generate_dsa_keys(key_size=2048)
    return {
        'type': 'KeyGen',
        'message': 'DSA Keys generated successfully.',
        'pub_pem': pub_pem.decode('utf-8'),
        'priv_pem': priv_pem.decode('utf-8')
    }


def _handle_lab5_input(input_type):
    if input_type == 'string':
        return request.form.get('text_input', '').encode('utf-8'), 'Text Input'

    data_file = request.files.get('file_input')
    if data_file and data_file.filename != '':
        return data_file.read(), secure_filename(data_file.filename)

    return None, None


def _handle_lab5_sign(data_bytes, source_name, key_data):
    signature_hex = dsa_sign(data_bytes, key_data)
    output_filename = 'signature.sig'
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

    with open(output_path, 'w') as file_handle:
        file_handle.write(signature_hex)

    return {
        'type': 'Signature Created',
        'input': source_name,
        'signature_hex': signature_hex,
        'output': output_filename
    }


def _handle_lab5_verify(data_bytes, source_name, key_data):
    sig_type = request.form.get('sig_type')
    if sig_type == 'text':
        signature_hex = request.form.get('sig_text', '').strip()
    else:
        sig_file = request.files.get('sig_file')
        signature_hex = sig_file.read().decode('utf-8').strip() if sig_file else ''

    is_valid = dsa_verify(data_bytes, signature_hex, key_data)
    return {
        'type': 'Verification',
        'input': source_name,
        'success': is_valid
    }


def _handle_lab5_post(action, input_type, key_file):
    data_bytes, source_name = _handle_lab5_input(input_type)
    if data_bytes is None:
        return {'error': 'Please provide a file.'}

    if not key_file or key_file.filename == '':
        return {'error': 'Please provide the .pem key file.'}

    key_data = key_file.read()
    try:
        if action == 'sign':
            return _handle_lab5_sign(data_bytes, source_name, key_data)

        if action == 'verify':
            return _handle_lab5_verify(data_bytes, source_name, key_data)

        return None
    except Exception as e:
        if action == 'sign':
            return {'error': f'Signing failed. Ensure you uploaded a Private Key. Details: {str(e)}'}

        return {
            'error': f'Verification error. Ensure you uploaded a Public Key and a valid signature. Details: {str(e)}'
        }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/lab1', methods=['GET', 'POST'])
def lab1():
    results = None
    if request.method == 'POST':
        m = int(request.form.get('m'))
        a = int(request.form.get('a'))
        c = int(request.form.get('c'))
        x0 = int(request.form.get('x0'))
        num_count = int(request.form.get('num_count'))
        results = run_lab1_algorithm(m, a, c, x0, num_count)
    return render_template('lab1.html', results=results)


@app.route('/lab2', methods=['GET', 'POST'])
def lab2():
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        md5_hasher = MD5()

        if action == 'string':
            text = request.form.get('text_input', '')
            hash_val = md5_hasher.hash_string(text)
            result = {'type': 'String', 'input': text, 'hash': hash_val}
            _write_results_file(hash_val)

        elif action == 'file':
            file = request.files.get('file_input')
            if file and file.filename != '':
                original_filename = file.filename
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                hash_val = md5_hasher.hash_file(filepath)
                os.remove(filepath)
                result = {'type': 'File', 'input': original_filename, 'hash': hash_val}
                _write_results_file(hash_val)

        elif action == 'integrity':
            file = request.files.get('file_check')
            expected = request.form.get('expected_hash', '').strip().lower()
            if file and file.filename != '' and expected:
                filename = secure_filename(file.filename)
                original_filename = file.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                hash_val = md5_hasher.hash_file(filepath)
                os.remove(filepath)
                is_intact = (hash_val == expected)
                result = {
                    'type': 'Integrity',
                    'input': original_filename,
                    'hash': hash_val,
                    'expected': expected,
                    'intact': is_intact
                }
    return render_template('lab2.html', result=result)


@app.route('/lab3', methods=['GET', 'POST'])
def lab3():
    result = None
    if request.method == 'POST':
        result = _handle_lab3_post(request.form.get('action'), request.files.get('file_input'), request.form.get('password'))
    return render_template('lab3.html', result=result)


@app.route('/lab4', methods=['GET', 'POST'])
def lab4():
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'generate_keys':
            result = _handle_lab4_generate_keys()
        elif action in ['encrypt', 'decrypt']:
            result = _handle_lab4_post(action, request.files.get('file_input'), request.files.get('key_input'))

    return render_template('lab4.html', result=result)


@app.route('/lab5', methods=['GET', 'POST'])
def lab5():
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'generate_keys':
            result = _handle_lab5_generate_keys()
        elif action in ['sign', 'verify']:
            result = _handle_lab5_post(action, request.form.get('input_type'), request.files.get('key_input'))

    return render_template(LAB5_TEMPLATE, result=result)


@app.route('/download')
def download_file():
    return send_file(RESULTS_FILE, as_attachment=True)


@app.route('/download_file/<filename>')
def download_specific_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
    return send_file(filepath, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)