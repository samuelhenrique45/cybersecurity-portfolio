
# ============================================================================
# CRIPTOGRAFIA HÍBRIDA: RSA + ECC + AES - CORREÇÃO DE BUGS
# Sistema completo: troca de chaves ECC + cifragem AES + assinatura RSA/ECDSA
# ============================================================================

import os
import sys
import math
import random
import hashlib
import time
import json
import base64
from typing import Tuple, Optional, List, Dict
from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ============================================================================
# PARTE 1: RSA DO ZERO
# ============================================================================

class RSA_Manual:
    """Implementação completa do RSA sem bibliotecas externas"""
    
    @staticmethod
    def is_prime_miller_rabin(n: int, k: int = 40) -> bool:
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False
        
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    @staticmethod
    def generate_prime(bits: int = 512) -> int:
        while True:
            p = random.getrandbits(bits)
            p |= (1 << bits - 1) | 1
            if RSA_Manual.is_prime_miller_rabin(p):
                return p
    
    @staticmethod
    def egcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        g, x1, y1 = RSA_Manual.egcd(b % a, a)
        return g, y1 - (b // a) * x1, x1
    
    @staticmethod
    def modinv(a: int, m: int) -> int:
        g, x, _ = RSA_Manual.egcd(a, m)
        if g != 1:
            raise ValueError("Inverso não existe")
        return x % m
    
    @staticmethod
    def generate_keypair(bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        p = RSA_Manual.generate_prime(bits // 2)
        q = RSA_Manual.generate_prime(bits // 2)
        while q == p:
            q = RSA_Manual.generate_prime(bits // 2)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = 65537
        if math.gcd(e, phi) != 1:
            e = 3
            while math.gcd(e, phi) != 1:
                e += 2
        
        d = RSA_Manual.modinv(e, phi)
        
        return ((e, n), (d, n))
    
    @staticmethod
    def encrypt(msg: int, public_key: Tuple[int, int]) -> int:
        e, n = public_key
        return pow(msg, e, n)
    
    @staticmethod
    def decrypt(cipher: int, private_key: Tuple[int, int]) -> int:
        d, n = private_key
        return pow(cipher, d, n)
    
    @staticmethod
    def sign(msg_hash: int, private_key: Tuple[int, int]) -> int:
        d, n = private_key
        return pow(msg_hash, d, n)
    
    @staticmethod
    def verify(msg_hash: int, signature: int, public_key: Tuple[int, int]) -> bool:
        e, n = public_key
        decrypted = pow(signature, e, n)
        return decrypted == msg_hash


# ============================================================================
# PARTE 2: ECC (CURVAS ELÍPTICAS) DO ZERO
# ============================================================================

class Point:
    def __init__(self, x: int, y: int, curve: 'EllipticCurve'):
        self.x = x
        self.y = y
        self.curve = curve
    
    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y and self.curve == other.curve
    
    def __repr__(self):
        return f"Point({self.x}, {self.y})"


class EllipticCurve:
    # Parâmetros secp256k1 (Bitcoin)
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7
    G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    def __init__(self, p: int = P, a: int = A, b: int = B):
        self.p = p
        self.a = a % p
        self.b = b % p
        self.g = Point(self.G_X, self.G_Y, self)
        self.n = self.N
    
    def is_on_curve(self, point: Point) -> bool:
        left = pow(point.y, 2, self.p)
        right = (pow(point.x, 3, self.p) + self.a * point.x + self.b) % self.p
        return left == right
    
    def point_double(self, point: Point) -> Point:
        if point is None:
            return None
        num = (3 * pow(point.x, 2, self.p) + self.a) % self.p
        den = (2 * point.y) % self.p
        slope = (num * pow(den, self.p - 2, self.p)) % self.p
        x3 = (pow(slope, 2, self.p) - 2 * point.x) % self.p
        y3 = (slope * (point.x - x3) - point.y) % self.p
        return Point(x3, y3, self)
    
    def point_add(self, p1: Point, p2: Point) -> Point:
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        if p1.x == p2.x and p1.y == p2.y:
            return self.point_double(p1)
        num = (p2.y - p1.y) % self.p
        den = (p2.x - p1.x) % self.p
        slope = (num * pow(den, self.p - 2, self.p)) % self.p
        x3 = (pow(slope, 2, self.p) - p1.x - p2.x) % self.p
        y3 = (slope * (p1.x - x3) - p1.y) % self.p
        return Point(x3, y3, self)
    
    def scalar_mult(self, k: int, point: Point) -> Point:
        if k == 0 or point is None:
            return None
        result = None
        addend = point
        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_double(addend)
            k >>= 1
        return result


class ECC_Manual:
    def __init__(self):
        self.curve = EllipticCurve()
        self.private_key = None
        self.public_key = None
    
    def generate_keypair(self) -> Tuple[int, Point]:
        private_key = random.randrange(1, self.curve.n)
        public_key = self.curve.scalar_mult(private_key, self.curve.g)
        return private_key, public_key
    
    def ecdh_shared_secret(self, private_key: int, other_public: Point) -> bytes:
        point = self.curve.scalar_mult(private_key, other_public)
        if point is None:
            raise ValueError("Falha no acordo ECDH")
        return point.x.to_bytes(32, 'big')
    
    def ecdsa_sign(self, message_hash: int, private_key: int) -> Tuple[int, int]:
        z = message_hash % self.curve.n
        while True:
            k = random.randrange(1, self.curve.n)
            kG = self.curve.scalar_mult(k, self.curve.g)
            r = kG.x % self.curve.n
            if r == 0:
                continue
            k_inv = pow(k, self.curve.n - 2, self.curve.n)
            s = (k_inv * (z + r * private_key)) % self.curve.n
            if s == 0:
                continue
            return (r, s)
    
    def ecdsa_verify(self, message_hash: int, signature: Tuple[int, int], public_key: Point) -> bool:
        r, s = signature
        if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
            return False
        z = message_hash % self.curve.n
        w = pow(s, self.curve.n - 2, self.curve.n)
        u1 = (z * w) % self.curve.n
        u2 = (r * w) % self.curve.n
        p1 = self.curve.scalar_mult(u1, self.curve.g)
        p2 = self.curve.scalar_mult(u2, public_key)
        point = self.curve.point_add(p1, p2)
        if point is None:
            return False
        return (point.x % self.curve.n) == r
    
    @staticmethod
    def hash_message(msg: bytes) -> int:
        return int.from_bytes(hashlib.sha256(msg).digest(), 'big')


# ============================================================================
# PARTE 3: CRIPTOGRAFIA HÍBRIDA (CORRIGIDA)
# ============================================================================

class HybridEncryption:
    def __init__(self):
        self.aes_key_size = 32
        self.iv_size = 12
    
    def generate_ecc_keypair(self) -> Tuple[int, Point]:
        ecc = ECC_Manual()
        return ecc.generate_keypair()
    
    def generate_rsa_keypair(self, bits: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        return RSA_Manual.generate_keypair(bits)
    
    def derive_aes_key(self, shared_secret: bytes, salt: bytes = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', shared_secret, salt, 100000, self.aes_key_size)
        return key, salt
    
    def aes_gcm_encrypt(self, plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        iv = os.urandom(self.iv_size)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, iv, tag
    
    def aes_gcm_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    
    def hybrid_encrypt(self, plaintext: bytes, recipient_public_key: Point,
                       sender_ecc_private: int = None,
                       sign_with_rsa: bool = False, 
                       rsa_private_key: Tuple[int, int] = None) -> Dict:
        # Gerar par efêmero ECC
        ecc_ephemeral = ECC_Manual()
        ephemeral_priv, ephemeral_pub = ecc_ephemeral.generate_keypair()
        
        # Acordo ECDH
        shared_secret = ecc_ephemeral.ecdh_shared_secret(ephemeral_priv, recipient_public_key)
        
        # Derivar chave AES
        aes_key, salt = self.derive_aes_key(shared_secret)
        
        # Cifrar dados
        ciphertext, iv, tag = self.aes_gcm_encrypt(plaintext, aes_key)
        
        encrypted_data = {
            'ephemeral_pub_x': hex(ephemeral_pub.x),
            'ephemeral_pub_y': hex(ephemeral_pub.y),
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode()
        }
        
        # Assinatura
        if sender_ecc_private is not None:
            msg_for_sig = ciphertext + iv + tag + salt
            msg_hash = ECC_Manual.hash_message(msg_for_sig)
            
            if sign_with_rsa and rsa_private_key:
                signature = RSA_Manual.sign(msg_hash, rsa_private_key)
                encrypted_data['signature'] = hex(signature)
                encrypted_data['signature_type'] = 'rsa'
                encrypted_data['rsa_public_key'] = {
                    'e': rsa_private_key[0],  # Atenção: isso não é correto na prática
                    'n': hex(rsa_private_key[1])
                }
            else:
                r, s = ecc_ephemeral.ecdsa_sign(msg_hash, sender_ecc_private)
                encrypted_data['signature'] = {'r': hex(r), 's': hex(s)}
                encrypted_data['signature_type'] = 'ecdsa'
        
        return encrypted_data
    
    def hybrid_decrypt(self, encrypted_data: Dict, recipient_private_key: int,
                       sender_public_key: Point = None,
                       sender_rsa_public_key: Tuple[int, int] = None,
                       verify_signature: bool = True) -> bytes:
        # Reconstruir chave pública efêmera
        from_hex = lambda s: int(s, 16) if isinstance(s, str) else s
        ephemeral_pub = Point(
            from_hex(encrypted_data['ephemeral_pub_x']),
            from_hex(encrypted_data['ephemeral_pub_y']),
            EllipticCurve()
        )
        
        # Acordo ECDH
        ecc = ECC_Manual()
        shared_secret = ecc.ecdh_shared_secret(recipient_private_key, ephemeral_pub)
        
        # Derivar chave AES
        salt = base64.b64decode(encrypted_data['salt'])
        aes_key, _ = self.derive_aes_key(shared_secret, salt)
        
        # Decifrar
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        plaintext = self.aes_gcm_decrypt(ciphertext, aes_key, iv, tag)
        
        # Verificar assinatura
        if verify_signature and 'signature' in encrypted_data and sender_public_key:
            msg_for_sig = ciphertext + iv + tag + salt
            msg_hash = ECC_Manual.hash_message(msg_for_sig)
            
            sig_type = encrypted_data.get('signature_type', 'ecdsa')
            if sig_type == 'rsa':
                if sender_rsa_public_key is None:
                    raise ValueError("Chave pública RSA necessária para verificar assinatura")
                signature = int(encrypted_data['signature'], 16)
                is_valid = RSA_Manual.verify(msg_hash, signature, sender_rsa_public_key)
            else:
                r = int(encrypted_data['signature']['r'], 16)
                s = int(encrypted_data['signature']['s'], 16)
                is_valid = ecc.ecdsa_verify(msg_hash, (r, s), sender_public_key)
            
            if not is_valid:
                raise ValueError("Assinatura inválida!")
        
        return plaintext


# ============================================================================
# PARTE 4: SISTEMA DE COMUNICAÇÃO SEGURA (CORRIGIDO)
# ============================================================================

class SecureCommunicationSystem:
    def __init__(self, name: str):
        self.name = name
        self.ecc = ECC_Manual()
        self.hybrid = HybridEncryption()
        
        # Gerar chaves ECC para troca de chaves
        self.ecc_private, self.ecc_public = self.hybrid.generate_ecc_keypair()
        
        # Gerar chaves RSA para assinatura
        self.rsa_public, self.rsa_private = self.hybrid.generate_rsa_keypair(1024)
        
        print(f"[{name}] Chaves geradas:")
        print(f"  ECC Priv: {hex(self.ecc_private)[:20]}...")
        print(f"  ECC Pub: ({hex(self.ecc_public.x)[:16]}..., {hex(self.ecc_public.y)[:16]}...)")
        print(f"  RSA Pub: (e={self.rsa_public[0]}, n={hex(self.rsa_public[1])[:20]}...)")
    
    def send_encrypted_ecc_sign(self, message: str, recipient_public_key: Point) -> Dict:
        """Envia mensagem cifrada com assinatura ECDSA"""
        print(f"\n[{self.name}] Enviando mensagem cifrada (assinatura ECDSA)...")
        plaintext = message.encode('utf-8')
        encrypted = self.hybrid.hybrid_encrypt(
            plaintext, recipient_public_key,
            sender_ecc_private=self.ecc_private,
            sign_with_rsa=False
        )
        return encrypted
    
    def send_encrypted_rsa_sign(self, message: str, recipient_public_key: Point) -> Dict:
        """Envia mensagem cifrada com assinatura RSA"""
        print(f"\n[{self.name}] Enviando mensagem cifrada (assinatura RSA)...")
        plaintext = message.encode('utf-8')
        encrypted = self.hybrid.hybrid_encrypt(
            plaintext, recipient_public_key,
            sender_ecc_private=self.ecc_private,
            sign_with_rsa=True,
            rsa_private_key=self.rsa_private
        )
        return encrypted
    
    def receive_encrypted(self, encrypted_data: Dict, sender_public_key: Point = None,
                          sender_rsa_public_key: Tuple[int, int] = None,
                          verify: bool = True) -> str:
        """Recebe e decifra mensagem"""
        print(f"\n[{self.name}] Recebendo e decifrando mensagem...")
        plaintext = self.hybrid.hybrid_decrypt(
            encrypted_data, self.ecc_private,
            sender_public_key, sender_rsa_public_key, verify
        )
        return plaintext.decode('utf-8')


# ============================================================================
# PARTE 5: DEMONSTRAÇÃO COMPLETA
# ============================================================================

def demo_hybrid_encryption():
    print("=" * 70)
    print("     CRIPTOGRAFIA HÍBRIDA: ECC + AES + ASSINATURA DIGITAL")
    print("=" * 70)
    
    # Criar usuários
    alice = SecureCommunicationSystem("Alice")
    bob = SecureCommunicationSystem("Bob")
    
    mensagem = """
    === DOCUMENTO SECRETO ===
    Operação: Coelho Branco
    Data: 25/12/2024
    Senha: S3nh4_S3cr3t4_2024!
    """
    
    print(f"\n📝 MENSAGEM ORIGINAL:")
    print(mensagem)
    
    # Teste com assinatura ECDSA
    print("\n" + "-" * 50)
    print("TESTE 1: Assinatura ECDSA")
    print("-" * 50)
    
    encrypted_ecdsa = alice.send_encrypted_ecc_sign(mensagem, bob.ecc_public)
    decrypted_ecdsa = bob.receive_encrypted(encrypted_ecdsa, alice.ecc_public, verify=True)
    
    if decrypted_ecdsa == mensagem:
        print("✅ ECDSA: Mensagem cifrada e verificada com sucesso!")
    else:
        print("❌ ECDSA: Falha na decifragem!")
    
    # Teste com assinatura RSA
    print("\n" + "-" * 50)
    print("TESTE 2: Assinatura RSA")
    print("-" * 50)
    
    encrypted_rsa = alice.send_encrypted_rsa_sign(mensagem, bob.ecc_public)
    decrypted_rsa = bob.receive_encrypted(encrypted_rsa, alice.ecc_public, alice.rsa_public, verify=True)
    
    if decrypted_rsa == mensagem:
        print("✅ RSA: Mensagem cifrada e verificada com sucesso!")
    else:
        print("❌ RSA: Falha na decifragem!")
    
    # Teste de integridade
    print("\n" + "-" * 50)
    print("TESTE 3: Tentativa de adulteração")
    print("-" * 50)
    
    tampered = encrypted_ecdsa.copy()
    tampered['ciphertext'] = base64.b64encode(b"X" * 32).decode()
    
    try:
        bob.receive_encrypted(tampered, alice.ecc_public, verify=True)
        print("❌ ERRO: Mensagem adulterada foi aceita!")
    except ValueError as e:
        print(f"✅ SUCESSO: Mensagem adulterada REJEITADA: {e}")
    
    # Teste de falsificação
    print("\n" + "-" * 50)
    print("TESTE 4: Tentativa de falsificação")
    print("-" * 50)
    
    mallory = SecureCommunicationSystem("Mallory")
    fake_encrypted = mallory.send_encrypted_ecc_sign("Mensagem falsa!", bob.ecc_public)
    
    try:
        bob.receive_encrypted(fake_encrypted, alice.ecc_public, verify=True)
        print("❌ ERRO: Assinatura falsificada foi aceita!")
    except ValueError as e:
        print(f"✅ SUCESSO: Assinatura falsificada REJEITADA: {e}")


def demo_key_exchange():
    print("\n" + "=" * 70)
    print("     ACORDO DE CHAVES ECDH")
    print("=" * 70)
    
    alice_ecc = ECC_Manual()
    bob_ecc = ECC_Manual()
    
    alice_priv, alice_pub = alice_ecc.generate_keypair()
    bob_priv, bob_pub = bob_ecc.generate_keypair()
    
    alice_secret = alice_ecc.ecdh_shared_secret(alice_priv, bob_pub)
    bob_secret = bob_ecc.ecdh_shared_secret(bob_priv, alice_pub)
    
    print(f"\n🔐 Segredo compartilhado (Alice): {alice_secret.hex()[:40]}...")
    print(f"🔐 Segredo compartilhado (Bob):   {bob_secret.hex()[:40]}...")
    print(f"\n✅ Segredos iguais: {alice_secret == bob_secret}")


def main():
    print("=" * 70)
    print("   🔐 CRIPTOGRAFIA HÍBRIDA: RSA + ECC + AES (CORRIGIDO) 🔐")
    print("=" * 70)
    
    while True:
        print("\n" + "-" * 50)
        print("[1] Demo: Criptografia Híbrida (ECC + AES + Assinatura)")
        print("[2] Demo: Acordo de Chaves ECDH")
        print("[3] Sair")
        print("-" * 50)
        
        op = input("Opção: ").strip()
        
        if op == "1":
            demo_hybrid_encryption()
        elif op == "2":
            demo_key_exchange()
        elif op == "3":
            print("\n🔒 Encerrando...")
            break
        else:
            print("Opção inválida")


if __name__ == "__main__":
try:
        from Crypt.Cipher import AES
        main()
    except ImportError:
        print("Erro: pycryptodome não instalado. Instale com: pip install pycryptodome")
    except Exception as e:
        print(f"Erro: {e}")
        import traceback
        traceback.print_exc()
`