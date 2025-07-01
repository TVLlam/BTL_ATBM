from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
import json
import os
import hashlib
import secrets
import socket
import threading
import time
from datetime import datetime
import base64

# Import các thuật toán mã hóa đã tách riêng
from crypto import RSAHandler, DESHandler, HashHandler, FileProcessor

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Cấu hình thư mục
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_files'
DECRYPTED_FOLDER = 'decrypted_files'
KEYS_FOLDER = 'keys'
DATA_FOLDER = 'data'

# Tạo các thư mục cần thiết
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER, KEYS_FOLDER, DATA_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# File lưu trữ dữ liệu
USERS_FILE = os.path.join(DATA_FOLDER, 'users.json')
TRANSACTIONS_FILE = os.path.join(DATA_FOLDER, 'transactions.json')
ADMIN_FILE = os.path.join(DATA_FOLDER, 'admin.json')

# Socket server configuration
SOCKET_HOST = 'localhost'
SOCKET_PORT = 9999
socket_server = None

# Khởi tạo các handler
rsa_handler = RSAHandler()
des_handler = DESHandler()
hash_handler = HashHandler()
file_processor = FileProcessor()

# Biến để tránh duplicate transactions
processing_files = set()

# Khởi tạo dữ liệu mặc định
def init_data():
    # Khởi tạo file users.json
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f, ensure_ascii=False, indent=2)
    
    # Khởi tạo file transactions.json
    if not os.path.exists(TRANSACTIONS_FILE):
        with open(TRANSACTIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False, indent=2)
    
    # Khởi tạo file admin.json
    if not os.path.exists(ADMIN_FILE):
        admin_data = {
            'username': 'admin',
            'password': hashlib.sha256('admin123'.encode()).hexdigest()
        }
        with open(ADMIN_FILE, 'w', encoding='utf-8') as f:
            json.dump(admin_data, f, ensure_ascii=False, indent=2)

# Khởi tạo khóa RSA cho hệ thống
def init_system_keys():
    rsa_handler.save_system_keys(KEYS_FOLDER)

# Socket Server để xử lý giao tiếp thực tế
class SocketServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
    def start(self):
        """Khởi động socket server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"Socket server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"Connection from {address}")
                    
                    # Xử lý client trong thread riêng
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        print(f"Socket error: {e}")
                    break
                    
        except Exception as e:
            print(f"Failed to start socket server: {e}")
    
    def receive_large_data(self, client_socket, expected_size=None):
        """Nhận dữ liệu lớn với buffer động"""
        try:
            # Nhận header để biết kích thước data
            header = client_socket.recv(4).decode('utf-8')
            if not header.isdigit():
                # Fallback: nhận theo cách cũ nhưng với buffer lớn hơn
                return self.receive_data_with_large_buffer(client_socket, header)
            
            data_size = int(header)
            print(f"Expecting {data_size} bytes of data")
            
            # Nhận data theo chunks
            received_data = b''
            remaining = data_size
            
            while remaining > 0:
                chunk_size = min(remaining, 65536)  # 64KB chunks
                chunk = client_socket.recv(chunk_size)
                if not chunk:
                    break
                received_data += chunk
                remaining -= len(chunk)
            
            return received_data.decode('utf-8')
            
        except Exception as e:
            print(f"Error receiving large data: {e}")
            return None
    
    def receive_data_with_large_buffer(self, client_socket, first_chunk=""):
        """Nhận dữ liệu với buffer lớn (fallback method)"""
        try:
            data_parts = [first_chunk] if first_chunk else []
            
            # Tăng buffer size lên 256KB
            while True:
                try:
                    chunk = client_socket.recv(262144)  # 256KB buffer
                    if not chunk:
                        break
                    data_parts.append(chunk.decode('utf-8'))
                    
                    # Kiểm tra xem đã nhận đủ JSON chưa
                    current_data = ''.join(data_parts)
                    try:
                        json.loads(current_data)
                        # Nếu parse được JSON thì đã nhận đủ
                        return current_data
                    except json.JSONDecodeError:
                        # Chưa đủ, tiếp tục nhận
                        continue
                        
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"Error in receive_data_with_large_buffer: {e}")
                    break
            
            return ''.join(data_parts)
            
        except Exception as e:
            print(f"Error in fallback receive method: {e}")
            return None
            
    def handle_client(self, client_socket, address):
        """Xử lý kết nối từ client theo đúng giao thức đề tài"""
        try:
            # Set socket timeout
            client_socket.settimeout(60)  # 60 seconds timeout
            
            # 1. Handshake
            print(f"[{address}] Waiting for handshake...")
            data = client_socket.recv(1024).decode('utf-8')
            print(f"[{address}] Received: {data}")
            
            if data == "Hello!":
                client_socket.send("Ready!".encode('utf-8'))
                print(f"[{address}] Handshake successful")
            else:
                client_socket.send("NACK: Invalid handshake".encode('utf-8'))
                print(f"[{address}] Handshake failed")
                client_socket.close()
                return
            
            # 2. Nhận metadata và SessionKey với buffer lớn
            print(f"[{address}] Waiting for metadata...")
            metadata_data = self.receive_data_with_large_buffer(client_socket)
            
            if not metadata_data:
                client_socket.send("NACK: Failed to receive metadata".encode('utf-8'))
                print(f"[{address}] Failed to receive metadata")
                client_socket.close()
                return
            
            try:
                metadata_json = json.loads(metadata_data)
                print(f"[{address}] Received metadata for user: {metadata_json['username']}")
            except json.JSONDecodeError as e:
                client_socket.send(f"NACK: Invalid metadata JSON: {str(e)}".encode('utf-8'))
                print(f"[{address}] Metadata JSON parse error: {e}")
                client_socket.close()
                return
            
            # Xác minh metadata signature
            if not self.verify_metadata_signature(metadata_json):
                client_socket.send("NACK: Invalid metadata signature".encode('utf-8'))
                print(f"[{address}] Metadata signature verification failed")
                client_socket.close()
                return
            
            # Giải mã SessionKey
            session_key = self.decrypt_session_key(metadata_json['encrypted_session_key'])
            if not session_key:
                client_socket.send("NACK: Cannot decrypt session key".encode('utf-8'))
                print(f"[{address}] Session key decryption failed")
                client_socket.close()
                return
            
            client_socket.send("ACK: Metadata verified".encode('utf-8'))
            print(f"[{address}] Metadata verified successfully")
            
            # 3. Nhận các phần file với buffer lớn
            file_parts = []
            parts_count = metadata_json['metadata']['parts']
            print(f"[{address}] Expecting {parts_count} file parts...")
            
            for i in range(parts_count):
                print(f"[{address}] Waiting for part {i+1}...")
                
                # Nhận part data với buffer lớn
                part_data = self.receive_data_with_large_buffer(client_socket)
                
                if not part_data:
                    nack_msg = f"NACK: Failed to receive part {i+1}"
                    client_socket.send(nack_msg.encode('utf-8'))
                    print(f"[{address}] Failed to receive part {i+1}")
                    client_socket.close()
                    return
                
                try:
                    part_json = json.loads(part_data)
                    print(f"[{address}] Part {i+1} JSON parsed successfully, size: {len(part_data)} bytes")
                except json.JSONDecodeError as e:
                    nack_msg = f"NACK: Part {i+1} JSON parse error: {str(e)}"
                    client_socket.send(nack_msg.encode('utf-8'))
                    print(f"[{address}] Part {i+1} JSON parse error: {e}")
                    client_socket.close()
                    return
                
                # Xác minh từng phần
                if self.verify_part(part_json, session_key, metadata_json['username']):
                    file_parts.append(part_json)
                    ack_msg = f"ACK: Part {i+1} verified"
                    client_socket.send(ack_msg.encode('utf-8'))
                    print(f"[{address}] Part {i+1} verified successfully")
                else:
                    nack_msg = f"NACK: Part {i+1} integrity failed"
                    client_socket.send(nack_msg.encode('utf-8'))
                    print(f"[{address}] Part {i+1} verification failed")
                    client_socket.close()
                    return
            
            # 4. Ghép và lưu file
            if self.reconstruct_file(file_parts, session_key, metadata_json):
                client_socket.send("ACK: File received successfully".encode('utf-8'))
                print(f"[{address}] File received and reconstructed successfully")
            else:
                client_socket.send("NACK: File reconstruction failed".encode('utf-8'))
                print(f"[{address}] File reconstruction failed")
                
        except Exception as e:
            print(f"Error handling client {address}: {e}")
            try:
                client_socket.send(f"NACK: Server error - {str(e)}".encode('utf-8'))
            except:
                pass
        finally:
            client_socket.close()
            print(f"[{address}] Connection closed")
    
    def verify_metadata_signature(self, metadata_json):
        """Xác minh chữ ký metadata"""
        try:
            # Lấy khóa công khai của user
            users = load_json_file(USERS_FILE)
            username = metadata_json['username']
            
            if username not in users or not users[username].get('public_key'):
                print(f"User {username} not found or no public key")
                return False
            
            user_public_key_pem = users[username]['public_key']
            metadata = metadata_json['metadata']
            signature = base64.b64decode(metadata_json['metadata_signature'])
            
            # Verify signature using file processor
            return file_processor.verify_metadata_signature(metadata, signature, user_public_key_pem)
            
        except Exception as e:
            print(f"Metadata signature verification failed: {e}")
            return False
    
    def decrypt_session_key(self, encrypted_session_key_b64):
        """Giải mã SessionKey"""
        try:
            # Lấy khóa riêng của hệ thống
            system_private_key_pem, _ = rsa_handler.load_system_keys(KEYS_FOLDER)
            
            # Giải mã SessionKey
            encrypted_session_key = base64.b64decode(encrypted_session_key_b64)
            session_key = rsa_handler.decrypt_session_key(encrypted_session_key, system_private_key_pem)
            
            if session_key:
                print("Session key decrypted successfully")
                return session_key
            else:
                print("Session key decryption failed")
                return None
        except Exception as e:
            print(f"Session key decryption failed: {e}")
            return None
    
    def verify_part(self, part_json, session_key, username):
        """Xác minh từng phần file theo đúng giao thức"""
        try:
            # Giải mã dữ liệu
            iv = base64.b64decode(part_json['iv'])
            cipher = base64.b64decode(part_json['cipher'])  # Đổi từ 'ciphertext' thành 'cipher'
            received_hash = part_json['hash']  # Hex format theo đề
            signature = base64.b64decode(part_json['sig'])  # Đổi từ 'signature' thành 'sig'
            
            # Kiểm tra hash
            if not hash_handler.verify_part_hash(iv, cipher, received_hash):
                print(f"Hash verification failed")
                return False
            
            # Xác minh chữ ký
            users = load_json_file(USERS_FILE)
            if username not in users or not users[username].get('public_key'):
                print(f"User {username} not found for signature verification")
                return False
            
            user_public_key_pem = users[username]['public_key']
            
            # Tạo dữ liệu để verify signature: IV || cipher || hash
            data_to_verify = iv + cipher + bytes.fromhex(received_hash)
            
            if not rsa_handler.verify_signature(data_to_verify, signature, user_public_key_pem):
                print(f"Signature verification failed")
                return False
            
            print(f"Part signature verified successfully")
            return True
        except Exception as e:
            print(f"Part verification failed: {e}")
            return False
    
    def reconstruct_file(self, file_parts, session_key, metadata_json):
        """Ghép lại file từ các phần đã giải mã"""
        try:
            decrypted_parts = []
            
            # Giải mã từng phần
            for i, part in enumerate(file_parts):
                iv = base64.b64decode(part['iv'])
                cipher = base64.b64decode(part['cipher'])  # Đổi từ 'ciphertext' thành 'cipher'
                
                # Giải mã bằng DES
                decrypted_data = des_handler.decrypt_file_part(cipher, session_key, iv)
                if decrypted_data is None:
                    print(f"Part {i+1} decryption failed")
                    return False
                
                decrypted_parts.append(decrypted_data)
                print(f"Part {i+1} decrypted successfully")
            
            # Ghép các phần lại
            complete_file = file_processor.reconstruct_file(decrypted_parts)
            
            # Lưu file
            filename = metadata_json['metadata']['filename']
            username = metadata_json['username']
            file_path = os.path.join(DECRYPTED_FOLDER, f"{username}_{filename}")
            
            with open(file_path, 'wb') as f:
                f.write(complete_file)
            
            print(f"File reconstructed and saved: {file_path}")
            return True
        except Exception as e:
            print(f"File reconstruction failed: {e}")
            return False
    
    def stop(self):
        """Dừng socket server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

# Hàm tiện ích
def load_json_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {} if 'users' in filepath or 'admin' in filepath else []

def save_json_file(filepath, data):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Routes cho Giảng viên
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_json_file(USERS_FILE)
        
        if username in users and users[username]['password'] == hash_password(password):
            session['user'] = username
            session['user_type'] = 'teacher'
            return redirect(url_for('dashboard'))
        else:
            flash('Tên đăng nhập hoặc mật khẩu không đúng!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        users = load_json_file(USERS_FILE)
        
        if username in users:
            flash('Tên đăng nhập đã tồn tại!', 'error')
        else:
            users[username] = {
                'password': hash_password(password),
                'email': email,
                'created_at': datetime.now().isoformat(),
                'public_key': None
            }
            save_json_file(USERS_FILE, users)
            flash('Đăng ký thành công! Vui lòng đăng nhập.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user'])

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Không có file được chọn!', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('Không có file được chọn!', 'error')
            return redirect(request.url)
        
        if file and file.filename.endswith('.txt'):
            # Tạo unique identifier để tránh duplicate
            file_id = f"{session['user']}_{file.filename}_{int(time.time())}"
            
            # Kiểm tra xem file này đã được xử lý chưa
            if file_id in processing_files:
                flash('File đang được xử lý, vui lòng đợi!', 'warning')
                return redirect(request.url)
            
            # Thêm vào danh sách đang xử lý
            processing_files.add(file_id)
            
            try:
                # Lưu file tạm thời
                temp_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.txt")
                file.save(temp_path)
                
                # Xử lý file và gửi qua socket
                result = process_and_send_file_via_socket(temp_path, session['user'])
                
                if result['success']:
                    flash('Gửi file thành công!', 'success')
                else:
                    flash(f'Gửi file thất bại: {result["error"]}', 'error')
                
                # Xóa file tạm
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                    
            finally:
                # Loại bỏ khỏi danh sách đang xử lý
                processing_files.discard(file_id)
        else:
            flash('Chỉ chấp nhận file .txt!', 'error')
    
    return render_template('upload.html')

@app.route('/keys', methods=['GET', 'POST'])
def manage_keys():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    users = load_json_file(USERS_FILE)
    user_data = users.get(session['user'], {})
    
    if request.method == 'POST':
        if 'generate' in request.form:
            # Tạo cặp khóa RSA mới
            private_key, public_key = rsa_handler.generate_key_pair()
            
            # Lưu khóa công khai vào database
            users[session['user']]['public_key'] = public_key
            save_json_file(USERS_FILE, users)
            
            # Trả về khóa riêng để người dùng tải xuống
            return render_template('keys.html', 
                                 has_public_key=True,
                                 private_key=private_key,
                                 public_key=public_key)
        
        elif 'upload' in request.form:
            public_key_text = request.form['public_key']
            try:
                # Kiểm tra tính hợp lệ của khóa
                rsa_handler.import_key(public_key_text)
                users[session['user']]['public_key'] = public_key_text
                save_json_file(USERS_FILE, users)
                flash('Tải lên khóa công khai thành công!', 'success')
            except:
                flash('Khóa công khai không hợp lệ!', 'error')
    
    return render_template('keys.html', has_public_key=user_data.get('public_key') is not None)

@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    transactions = load_json_file(TRANSACTIONS_FILE)
    user_transactions = [t for t in transactions if t.get('username') == session['user']]
    
    return render_template('history.html', transactions=user_transactions)

# Routes cho Admin
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin_data = load_json_file(ADMIN_FILE)
        
        if (username == admin_data['username'] and 
            hash_password(password) == admin_data['password']):
            session['user'] = username
            session['user_type'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Thông tin đăng nhập không đúng!', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    
    transactions = load_json_file(TRANSACTIONS_FILE)
    users = load_json_file(USERS_FILE)
    
    stats = {
        'total_users': len(users),
        'total_transactions': len(transactions),
        'successful_transactions': len([t for t in transactions if t.get('status') == 'success']),
        'failed_transactions': len([t for t in transactions if t.get('status') == 'failed'])
    }
    
    return render_template('admin_dashboard.html', stats=stats)

@app.route('/admin/transactions')
def admin_transactions():
    if session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    
    transactions = load_json_file(TRANSACTIONS_FILE)
    return render_template('admin_transactions.html', transactions=transactions)

@app.route('/admin/users')
def admin_users():
    if session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    
    users = load_json_file(USERS_FILE)
    return render_template('admin_users.html', users=users)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# API endpoints cho tải file
@app.route('/api/download/encrypted/<transaction_id>')
def download_encrypted_file(transaction_id):
    """Tải file đã mã hóa cho giảng viên"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Kiểm tra quyền truy cập
    transactions = load_json_file(TRANSACTIONS_FILE)
    transaction = next((t for t in transactions if t['id'] == transaction_id and t['username'] == session['user']), None)
    
    if not transaction:
        flash('Không tìm thấy giao dịch hoặc bạn không có quyền truy cập!', 'error')
        return redirect(url_for('history'))
    
    encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, f"{session['user']}_{transaction_id}.json")
    
    if os.path.exists(encrypted_file_path):
        return send_file(encrypted_file_path, 
                        as_attachment=True, 
                        download_name=f"encrypted_{transaction['filename']}_{transaction_id[:8]}.json",
                        mimetype='application/json')
    else:
        flash('File đã mã hóa không tồn tại!', 'error')
        return redirect(url_for('history'))

@app.route('/api/download/decrypted/<transaction_id>')
def download_decrypted_file(transaction_id):
    """Tải file đã giải mã cho admin"""
    if session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    
    transactions = load_json_file(TRANSACTIONS_FILE)
    transaction = next((t for t in transactions if t['id'] == transaction_id), None)
    
    if not transaction:
        flash('Không tìm thấy giao dịch!', 'error')
        return redirect(url_for('admin_transactions'))
    
    decrypted_file_path = os.path.join(DECRYPTED_FOLDER, f"{transaction['username']}_{transaction['filename']}")
    
    if os.path.exists(decrypted_file_path):
        return send_file(decrypted_file_path, 
                        as_attachment=True, 
                        download_name=f"decrypted_{transaction['filename']}",
                        mimetype='text/plain')
    else:
        flash('File đã giải mã không tồn tại!', 'error')
        return redirect(url_for('admin_transactions'))

# API endpoint cho thống kê người dùng
@app.route('/api/user-stats/<username>')
def get_user_stats(username):
    """API để lấy thống kê thực của người dùng"""
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        transactions = load_json_file(TRANSACTIONS_FILE)
        user_transactions = [t for t in transactions if t.get('username') == username]
        
        # Tính toán thống kê
        total_files = len(user_transactions)
        successful_files = len([t for t in user_transactions if t.get('status') == 'success'])
        failed_files = len([t for t in user_transactions if t.get('status') == 'failed'])
        success_rate = round((successful_files / total_files * 100) if total_files > 0 else 0, 1)
        
        # Tính tổng dung lượng
        total_size = sum([t.get('file_size', 0) for t in user_transactions])
        total_size_mb = round(total_size / (1024 * 1024), 2) if total_size > 0 else 0
        
        # Lấy hoạt động gần nhất
        last_activity = None
        if user_transactions:
            latest_transaction = max(user_transactions, key=lambda x: x.get('timestamp', ''))
            last_activity = latest_transaction.get('timestamp', '')
            if last_activity:
                try:
                    last_activity = datetime.fromisoformat(last_activity.replace('Z', '+00:00')).strftime('%d/%m/%Y %H:%M')
                except:
                    pass
        
        # Lấy 5 giao dịch gần nhất
        recent_transactions = sorted(user_transactions, key=lambda x: x.get('timestamp', ''), reverse=True)[:5]
        recent_transactions_formatted = []
        
        for t in recent_transactions:
            size_kb = round(t.get('file_size', 0) / 1024, 1) if t.get('file_size') else 0
            recent_transactions_formatted.append({
                'timestamp': t.get('timestamp', ''),
                'filename': t.get('filename', 'N/A'),
                'size_kb': size_kb,
                'status': t.get('status', 'unknown')
            })
        
        return jsonify({
            'total_files': total_files,
            'successful_files': successful_files,
            'failed_files': failed_files,
            'success_rate': success_rate,
            'total_size_mb': total_size_mb,
            'last_activity': last_activity,
            'recent_transactions': recent_transactions_formatted
        })
        
    except Exception as e:
        print(f"Error getting user stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def process_and_send_file_via_socket(file_path, username):
    """Xử lý và gửi file qua socket theo đúng giao thức đề tài"""
    try:
        # Lấy khóa hệ thống
        _, system_public_key_pem = rsa_handler.load_system_keys(KEYS_FOLDER)
        
        # Tạo khóa riêng tạm thời cho việc ký số (trong thực tế sẽ dùng khóa riêng của user)
        temp_private_key, temp_public_key = rsa_handler.generate_key_pair()
        
        # Cập nhật khóa công khai tương ứng vào database để verify được
        users = load_json_file(USERS_FILE)
        users[username]['public_key'] = temp_public_key
        save_json_file(USERS_FILE, users)
        
        # Xử lý file bằng file processor
        result = file_processor.process_file_for_sending(
            file_path, username, system_public_key_pem, temp_private_key
        )
        
        if not result['success']:
            return result
        
        # Gửi qua socket
        socket_result = send_via_socket(
            result['metadata'], 
            result['metadata_signature'], 
            result['encrypted_session_key'], 
            result['encrypted_parts'], 
            username
        )
        
        if socket_result['success']:
            # Tạo transaction ID duy nhất
            transaction_id = secrets.token_hex(16)
            
            # Lưu transaction
            transaction = {
                'id': transaction_id,
                'username': username,
                'filename': result['metadata']['filename'],
                'timestamp': result['metadata']['timestamp'],
                'status': 'success',
                'parts': len(result['encrypted_parts']),
                'encrypted_session_key': base64.b64encode(result['encrypted_session_key']).decode(),
                'file_size': result['metadata']['size']
            }
            
            transactions = load_json_file(TRANSACTIONS_FILE)
            transactions.append(transaction)
            save_json_file(TRANSACTIONS_FILE, transactions)
            
            # Lưu file đã mã hóa cho giảng viên tải xuống
            encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, f"{username}_{transaction_id}.json")
            with open(encrypted_file_path, 'w') as f:
                json.dump({
                    'metadata': result['metadata'],
                    'metadata_signature': base64.b64encode(result['metadata_signature']).decode(),
                    'encrypted_session_key': transaction['encrypted_session_key'],
                    'parts': result['encrypted_parts']
                }, f, indent=2)
            
            print(f"Transaction saved: {transaction_id}")
            return {'success': True, 'transaction_id': transaction_id}
        else:
            return socket_result
        
    except Exception as e:
        print(f"Error in process_and_send_file_via_socket: {e}")
        return {'success': False, 'error': str(e)}

def send_via_socket(metadata, metadata_signature, encrypted_session_key, encrypted_parts, username):
    """Gửi dữ liệu qua socket theo đúng giao thức đề tài với buffer lớn"""
    try:
        # Kết nối đến socket server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(60)  # 60 seconds timeout
        client_socket.connect((SOCKET_HOST, SOCKET_PORT))
        
        print(f"Connected to socket server at {SOCKET_HOST}:{SOCKET_PORT}")
        
        # 1. Handshake
        print("Sending handshake...")
        client_socket.send("Hello!".encode('utf-8'))
        response = client_socket.recv(1024).decode('utf-8')
        print(f"Handshake response: {response}")
        
        if response != "Ready!":
            return {'success': False, 'error': f'Handshake failed: {response}'}
        
        # 2. Gửi metadata và SessionKey
        print("Sending metadata...")
        metadata_package = {
            'username': username,
            'metadata': metadata,
            'metadata_signature': base64.b64encode(metadata_signature).decode(),
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode()
        }
        
        metadata_json = json.dumps(metadata_package)
        print(f"Metadata JSON size: {len(metadata_json)} bytes")
        
        # Gửi metadata với size header (nếu cần)
        client_socket.send(metadata_json.encode('utf-8'))
        response = client_socket.recv(1024).decode('utf-8')
        print(f"Metadata response: {response}")
        
        if not response.startswith("ACK"):
            return {'success': False, 'error': f'Metadata rejected: {response}'}
        
        # 3. Gửi từng phần file
        for i, part in enumerate(encrypted_parts):
            print(f"Sending part {i+1}...")
            part_json = json.dumps(part)
            part_size = len(part_json)
            print(f"Part {i+1} JSON size: {part_size} bytes")
            
            # Gửi part data
            client_socket.send(part_json.encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8')
            print(f"Part {i+1} response: {response}")
            
            if not response.startswith("ACK"):
                return {'success': False, 'error': f'Part {i+1} rejected: {response}'}
        
        # 4. Nhận phản hồi cuối cùng
        print("Waiting for final response...")
        final_response = client_socket.recv(1024).decode('utf-8')
        print(f"Final response: {final_response}")
        client_socket.close()
        
        if final_response.startswith("ACK"):
            return {'success': True, 'message': final_response}
        else:
            return {'success': False, 'error': final_response}
            
    except Exception as e:
        print(f"Socket communication error: {e}")
        return {'success': False, 'error': f'Socket communication failed: {str(e)}'}

def start_socket_server():
    """Khởi động socket server trong thread riêng"""
    global socket_server
    socket_server = SocketServer(SOCKET_HOST, SOCKET_PORT)
    server_thread = threading.Thread(target=socket_server.start)
    server_thread.daemon = True
    server_thread.start()
    print("Socket server thread started")

if __name__ == '__main__':
    print("Initializing system...")
    init_data()
    init_system_keys()
    
    # Khởi động socket server
    print("Starting socket server...")
    start_socket_server()
    
    # Đợi một chút để socket server khởi động
    time.sleep(1)
    
    # Khởi động Flask app
    print("Starting Flask application...")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)