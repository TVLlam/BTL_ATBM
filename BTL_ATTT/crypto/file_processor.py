"""
File Processor - Xử lý chia file và ghép file
"""

import os
import json
import base64
import secrets
from datetime import datetime
from .rsa_handler import RSAHandler
from .des_handler import DESHandler
from .hash_handler import HashHandler

class FileProcessor:
    def __init__(self):
        self.rsa_handler = RSAHandler()
        self.des_handler = DESHandler()
        self.hash_handler = HashHandler()
        self.parts_count = 3  # Chia thành 3 phần theo đề
    
    def split_file(self, file_content):
        """
        Chia file thành 3 phần
        Args:
            file_content: bytes - Nội dung file
        Returns:
            list - Danh sách 3 phần file
        """
        file_parts = []
        part_size = len(file_content) // self.parts_count
        
        for i in range(self.parts_count):
            if i == self.parts_count - 1:  # Phần cuối cùng
                part = file_content[i * part_size:]
            else:
                part = file_content[i * part_size:(i + 1) * part_size]
            file_parts.append(part)
        
        return file_parts
    
    def create_metadata(self, filename, file_size):
        """
        Tạo metadata cho file
        Args:
            filename: str - Tên file
            file_size: int - Kích thước file
        Returns:
            dict - Metadata
        """
        return {
            'filename': filename,
            'timestamp': datetime.now().isoformat(),
            'parts': self.parts_count,
            'size': file_size
        }
    
    def sign_metadata(self, metadata, private_key_pem):
        """
        Ký metadata bằng RSA/SHA-512
        Args:
            metadata: dict - Metadata
            private_key_pem: str - Khóa riêng RSA
        Returns:
            bytes - Chữ ký metadata
        """
        metadata_str = json.dumps(metadata, sort_keys=True)
        metadata_bytes = metadata_str.encode()
        return self.rsa_handler.sign_data(metadata_bytes, private_key_pem)
    
    def verify_metadata_signature(self, metadata, signature, public_key_pem):
        """
        Xác minh chữ ký metadata
        Args:
            metadata: dict - Metadata
            signature: bytes - Chữ ký
            public_key_pem: str - Khóa công khai RSA
        Returns:
            bool - True nếu chữ ký hợp lệ
        """
        metadata_str = json.dumps(metadata, sort_keys=True)
        metadata_bytes = metadata_str.encode()
        return self.rsa_handler.verify_signature(metadata_bytes, signature, public_key_pem)
    
    def encrypt_file_parts(self, file_parts, session_key, private_key_pem):
        """
        Mã hóa và ký số các phần file theo đúng cấu trúc đề tài
        Args:
            file_parts: list - Danh sách các phần file
            session_key: bytes - SessionKey DES
            private_key_pem: str - Khóa riêng để ký số
        Returns:
            list - Danh sách các phần đã mã hóa
        """
        encrypted_parts = []
        
        for i, part in enumerate(file_parts):
            # Mã hóa phần bằng DES
            iv, cipher = self.des_handler.encrypt_file_part(part, session_key)
            
            # Tính hash của IV || cipher (theo đề)
            hash_value = self.hash_handler.calculate_part_hash(iv, cipher)
            
            # Tạo dữ liệu để ký: IV || cipher || hash
            data_to_sign = iv + cipher + bytes.fromhex(hash_value)
            
            # Ký số bằng RSA/SHA-512
            signature = self.rsa_handler.sign_data(data_to_sign, private_key_pem)
            
            # Tạo gói tin theo cấu trúc đề (cipher và sig thay vì ciphertext và signature)
            encrypted_part = {
                'iv': base64.b64encode(iv).decode(),
                'cipher': base64.b64encode(cipher).decode(),  # Đúng tên theo đề
                'hash': hash_value,  # Hex format theo đề
                'sig': base64.b64encode(signature).decode()  # Đúng tên theo đề
            }
            
            encrypted_parts.append(encrypted_part)
            print(f"Part {i+1} encrypted: IV={len(iv)} bytes, Cipher={len(cipher)} bytes")
        
        return encrypted_parts
    
    def verify_and_decrypt_parts(self, encrypted_parts, session_key, public_key_pem):
        """
        Xác minh và giải mã các phần file
        Args:
            encrypted_parts: list - Danh sách các phần đã mã hóa
            session_key: bytes - SessionKey DES
            public_key_pem: str - Khóa công khai để verify
        Returns:
            list - Danh sách các phần đã giải mã hoặc None nếu thất bại
        """
        decrypted_parts = []
        
        for i, part in enumerate(encrypted_parts):
            # Giải mã dữ liệu
            iv = base64.b64decode(part['iv'])
            cipher = base64.b64decode(part['cipher'])  # Đúng tên theo đề
            received_hash = part['hash']
            signature = base64.b64decode(part['sig'])  # Đúng tên theo đề
            
            # Xác minh hash
            if not self.hash_handler.verify_part_hash(iv, cipher, received_hash):
                print(f"Part {i+1} hash verification failed")
                return None
            
            # Xác minh chữ ký
            data_to_verify = iv + cipher + bytes.fromhex(received_hash)
            if not self.rsa_handler.verify_signature(data_to_verify, signature, public_key_pem):
                print(f"Part {i+1} signature verification failed")
                return None
            
            # Giải mã phần
            decrypted_part = self.des_handler.decrypt_file_part(cipher, session_key, iv)
            if decrypted_part is None:
                print(f"Part {i+1} decryption failed")
                return None
            
            decrypted_parts.append(decrypted_part)
            print(f"Part {i+1} verified and decrypted successfully")
        
        return decrypted_parts
    
    def reconstruct_file(self, decrypted_parts):
        """
        Ghép các phần đã giải mã thành file hoàn chỉnh
        Args:
            decrypted_parts: list - Danh sách các phần đã giải mã
        Returns:
            bytes - File hoàn chỉnh
        """
        return b''.join(decrypted_parts)
    
    def process_file_for_sending(self, file_path, username, system_public_key_pem, user_private_key_pem):
        """
        Xử lý file để gửi (toàn bộ quy trình)
        Args:
            file_path: str - Đường dẫn file
            username: str - Tên người dùng
            system_public_key_pem: str - Khóa công khai hệ thống
            user_private_key_pem: str - Khóa riêng người dùng
        Returns:
            dict - Kết quả xử lý
        """
        try:
            # Đọc file
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Tạo metadata
            metadata = self.create_metadata(os.path.basename(file_path), len(file_content))
            
            # Ký metadata
            metadata_signature = self.sign_metadata(metadata, user_private_key_pem)
            
            # Tạo SessionKey
            session_key = self.des_handler.generate_session_key()
            
            # Mã hóa SessionKey bằng khóa công khai hệ thống
            encrypted_session_key = self.rsa_handler.encrypt_session_key(session_key, system_public_key_pem)
            
            # Chia file thành 3 phần
            file_parts = self.split_file(file_content)
            
            # Mã hóa và ký số các phần
            encrypted_parts = self.encrypt_file_parts(file_parts, session_key, user_private_key_pem)
            
            return {
                'success': True,
                'metadata': metadata,
                'metadata_signature': metadata_signature,
                'encrypted_session_key': encrypted_session_key,
                'encrypted_parts': encrypted_parts,
                'username': username
            }
            
        except Exception as e:
            print(f"File processing failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def process_received_file(self, metadata, metadata_signature, encrypted_session_key, 
                            encrypted_parts, username, system_private_key_pem, user_public_key_pem):
        """
        Xử lý file nhận được (toàn bộ quy trình)
        Args:
            metadata: dict - Metadata
            metadata_signature: bytes - Chữ ký metadata
            encrypted_session_key: bytes - SessionKey đã mã hóa
            encrypted_parts: list - Các phần đã mã hóa
            username: str - Tên người dùng
            system_private_key_pem: str - Khóa riêng hệ thống
            user_public_key_pem: str - Khóa công khai người dùng
        Returns:
            dict - Kết quả xử lý
        """
        try:
            # Xác minh chữ ký metadata
            if not self.verify_metadata_signature(metadata, metadata_signature, user_public_key_pem):
                return {'success': False, 'error': 'Invalid metadata signature'}
            
            # Giải mã SessionKey
            session_key = self.rsa_handler.decrypt_session_key(encrypted_session_key, system_private_key_pem)
            if not session_key:
                return {'success': False, 'error': 'Cannot decrypt session key'}
            
            # Xác minh và giải mã các phần
            decrypted_parts = self.verify_and_decrypt_parts(encrypted_parts, session_key, user_public_key_pem)
            if not decrypted_parts:
                return {'success': False, 'error': 'Part verification or decryption failed'}
            
            # Ghép file
            complete_file = self.reconstruct_file(decrypted_parts)
            
            return {
                'success': True,
                'file_content': complete_file,
                'metadata': metadata,
                'username': username
            }
            
        except Exception as e:
            print(f"File processing failed: {e}")
            return {'success': False, 'error': str(e)}