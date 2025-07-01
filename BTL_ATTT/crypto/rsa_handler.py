"""
RSA Handler - Xử lý mã hóa, giải mã và ký số RSA
Thuật toán: RSA 1024-bit với PKCS#1 v1.5 + SHA-512
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
import base64
import os

class RSAHandler:
    def __init__(self):
        self.key_size = 1024  # RSA 1024-bit theo đề
        
    def generate_key_pair(self):
        """
        Tạo cặp khóa RSA 1024-bit
        Returns: (private_key_pem, public_key_pem)
        """
        key = RSA.generate(self.key_size)
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()
        return private_key, public_key
    
    def import_key(self, key_data):
        """
        Import khóa từ PEM string hoặc bytes
        """
        if isinstance(key_data, str):
            key_data = key_data.encode()
        return RSA.import_key(key_data)
    
    def encrypt_session_key(self, session_key, public_key_pem):
        """
        Mã hóa SessionKey bằng RSA 1024-bit (PKCS#1 v1.5)
        Args:
            session_key: bytes - SessionKey cần mã hóa (8 bytes cho DES)
            public_key_pem: str - Khóa công khai RSA dạng PEM
        Returns:
            bytes - SessionKey đã mã hóa
        """
        public_key = self.import_key(public_key_pem)
        cipher_rsa = PKCS1_v1_5.new(public_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        return encrypted_session_key
    
    def decrypt_session_key(self, encrypted_session_key, private_key_pem):
        """
        Giải mã SessionKey bằng RSA 1024-bit (PKCS#1 v1.5)
        Args:
            encrypted_session_key: bytes - SessionKey đã mã hóa
            private_key_pem: str - Khóa riêng RSA dạng PEM
        Returns:
            bytes - SessionKey gốc hoặc None nếu thất bại
        """
        try:
            private_key = self.import_key(private_key_pem)
            cipher_rsa = PKCS1_v1_5.new(private_key)
            session_key = cipher_rsa.decrypt(encrypted_session_key, None)
            
            # Kiểm tra độ dài SessionKey cho DES (8 bytes)
            if session_key and len(session_key) == 8:
                return session_key
            return None
        except Exception as e:
            print(f"RSA decryption failed: {e}")
            return None
    
    def sign_data(self, data, private_key_pem):
        """
        Ký số dữ liệu bằng RSA/SHA-512 (PKCS#1 v1.5)
        Args:
            data: bytes - Dữ liệu cần ký
            private_key_pem: str - Khóa riêng RSA dạng PEM
        Returns:
            bytes - Chữ ký số
        """
        private_key = self.import_key(private_key_pem)
        hash_obj = SHA512.new(data)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return signature
    
    def verify_signature(self, data, signature, public_key_pem):
        """
        Xác minh chữ ký số bằng RSA/SHA-512 (PKCS#1 v1.5)
        Args:
            data: bytes - Dữ liệu gốc
            signature: bytes - Chữ ký số
            public_key_pem: str - Khóa công khai RSA dạng PEM
        Returns:
            bool - True nếu chữ ký hợp lệ
        """
        try:
            public_key = self.import_key(public_key_pem)
            hash_obj = SHA512.new(data)
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            return True
        except Exception as e:
            print(f"RSA signature verification failed: {e}")
            return False
    
    def load_system_keys(self, keys_folder):
        """
        Load khóa hệ thống từ thư mục
        Returns: (private_key_pem, public_key_pem)
        """
        private_key_path = os.path.join(keys_folder, 'system_private.pem')
        public_key_path = os.path.join(keys_folder, 'system_public.pem')
        
        with open(private_key_path, 'rb') as f:
            private_key = f.read().decode()
        
        with open(public_key_path, 'rb') as f:
            public_key = f.read().decode()
            
        return private_key, public_key
    
    def save_system_keys(self, keys_folder):
        """
        Tạo và lưu khóa hệ thống
        """
        private_key_path = os.path.join(keys_folder, 'system_private.pem')
        public_key_path = os.path.join(keys_folder, 'system_public.pem')
        
        if not os.path.exists(private_key_path):
            private_key_pem, public_key_pem = self.generate_key_pair()
            
            with open(private_key_path, 'w') as f:
                f.write(private_key_pem)
            
            with open(public_key_path, 'w') as f:
                f.write(public_key_pem)
            
            print(f"System RSA keys generated and saved to {keys_folder}")