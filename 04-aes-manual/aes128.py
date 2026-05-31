# ============================================================================
# IMPLEMENTAÇÃO MANUAL DO AES-128 (Rijndael) DO ZERO
# SEM BIBLIOTECAS CRIPTOGRÁFICAS - APENAS PYTHON PURO
# ============================================================================

import sys

# ============================================================================
# CONSTANTES AES
# ============================================================================

# S-Box (substituição não linear)
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-Box
INV_S_BOX = [0] * 256
for i, val in enumerate(S_BOX):
    INV_S_BOX[val] = i

# Rcon (Round constants)
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

# ============================================================================
# MULTIPLICAÇÃO EM GF(2^8)
# ============================================================================

def gf_mult(a, b):
    """Multiplicação em campo de Galois GF(2^8) com polinômio x^8 + x^4 + x^3 + x + 1"""
    resultado = 0
    for _ in range(8):
        if b & 1:
            resultado ^= a
        carry = a & 0x80
        a <<= 1
        if carry:
            a ^= 0x1b  # Polinômio irreduzível
        b >>= 1
    return resultado & 0xff

# ============================================================================
# OPERAÇÕES AES
# ============================================================================

def sub_bytes(state, inv=False):
    """Substituição de bytes usando S-Box"""
    sbox = INV_S_BOX if inv else S_BOX
    for i in range(16):
        state[i] = sbox[state[i]]
    return state

def shift_rows(state, inv=False):
    """Deslocamento de linhas (ShiftRows)"""
    matriz = [state[i:i+4] for i in range(0, 16, 4)]
    
    if inv:
        matriz[1] = matriz[1][-3:] + matriz[1][:1]
        matriz[2] = matriz[2][-2:] + matriz[2][:2]
        matriz[3] = matriz[3][-1:] + matriz[3][:3]
    else:
        matriz[1] = matriz[1][1:] + matriz[1][:1]
        matriz[2] = matriz[2][2:] + matriz[2][:2]
        matriz[3] = matriz[3][3:] + matriz[3][:3]
    
    return [byte for linha in matriz for byte in linha]

def mix_columns(state, inv=False):
    """Mistura de colunas (MixColumns)"""
    resultado = [0] * 16
    
    for col in range(4):
        idx = col * 4
        a = state[idx:idx+4]
        
        if inv:
            # Inverse MixColumns
            resultado[idx:idx+4] = [
                gf_mult(0x0e, a[0]) ^ gf_mult(0x0b, a[1]) ^ gf_mult(0x0d, a[2]) ^ gf_mult(0x09, a[3]),
                gf_mult(0x09, a[0]) ^ gf_mult(0x0e, a[1]) ^ gf_mult(0x0b, a[2]) ^ gf_mult(0x0d, a[3]),
                gf_mult(0x0d, a[0]) ^ gf_mult(0x09, a[1]) ^ gf_mult(0x0e, a[2]) ^ gf_mult(0x0b, a[3]),
                gf_mult(0x0b, a[0]) ^ gf_mult(0x0d, a[1]) ^ gf_mult(0x09, a[2]) ^ gf_mult(0x0e, a[3])
            ]
        else:
            # Forward MixColumns
            resultado[idx:idx+4] = [
                gf_mult(0x02, a[0]) ^ gf_mult(0x03, a[1]) ^ gf_mult(0x01, a[2]) ^ gf_mult(0x01, a[3]),
                gf_mult(0x01, a[0]) ^ gf_mult(0x02, a[1]) ^ gf_mult(0x03, a[2]) ^ gf_mult(0x01, a[3]),
                gf_mult(0x01, a[0]) ^ gf_mult(0x01, a[1]) ^ gf_mult(0x02, a[2]) ^ gf_mult(0x03, a[3]),
                gf_mult(0x03, a[0]) ^ gf_mult(0x01, a[1]) ^ gf_mult(0x01, a[2]) ^ gf_mult(0x02, a[3])
            ]
    
    return resultado

def add_round_key(state, round_key):
    """Adiciona a chave da rodada (XOR)"""
    return [state[i] ^ round_key[i] for i in range(16)]

# ============================================================================
# EXPANSÃO DE CHAVE
# ============================================================================

def rot_word(word):
    """RotWord - rotação cíclica de 4 bytes"""
    return word[1:] + word[:1]

def sub_word(word, inv=False):
    """SubWord - aplica S-Box em cada byte da palavra"""
    sbox = INV_S_BOX if inv else S_BOX
    return [sbox[b] for b in word]

def key_expansion(chave):
    """Expansão de chave AES-128: 16 bytes → 176 bytes (11 round keys)"""
    if len(chave) != 16:
        raise ValueError("Chave deve ter 16 bytes para AES-128")
    
    # Converter para lista de bytes
    chave_bytes = list(chave)
    palavras_expandidas = []
    
    # Copiar chave original para primeiras 4 palavras
    for i in range(4):
        palavras_expandidas.append(chave_bytes[i*4:(i+1)*4])
    
    # Gerar 40 palavras adicionais (10 rounds × 4 palavras)
    for i in range(4, 44):
        temp = palavras_expandidas[i-1][:]
        
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i//4]
        
        nova_palavra = [
            palavras_expandidas[i-4][0] ^ temp[0],
            palavras_expandidas[i-4][1] ^ temp[1],
            palavras_expandidas[i-4][2] ^ temp[2],
            palavras_expandidas[i-4][3] ^ temp[3]
        ]
        palavras_expandidas.append(nova_palavra)
    
    # Converter para round keys (16 bytes cada)
    round_keys = []
    for i in range(0, 44, 4):
        round_key = []
        for j in range(4):
            round_key.extend(palavras_expandidas[i + j])
        round_keys.append(round_key)
    
    return round_keys

# ============================================================================
# CIPHER PRINCIPAL
# ============================================================================

def aes_encrypt_bloco(plaintext, round_keys):
    """Cifra um único bloco de 16 bytes com AES-128"""
    if len(plaintext) != 16:
        raise ValueError("Plaintext deve ter 16 bytes")
    
    state = list(plaintext)
    
    # Round 0: AddRoundKey inicial
    state = add_round_key(state, round_keys[0])
    
    # Rounds 1-9
    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
    
    # Round 10 (sem MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    return bytes(state)

def aes_decrypt_bloco(ciphertext, round_keys):
    """Decifra um único bloco de 16 bytes com AES-128"""
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext deve ter 16 bytes")
    
    state = list(ciphertext)
    
    # Round 10 inverso
    state = add_round_key(state, round_keys[10])
    state = shift_rows(state, inv=True)
    state = sub_bytes(state, inv=True)
    
    # Rounds 9-1 inversos
    for round_num in range(9, 0, -1):
        state = add_round_key(state, round_keys[round_num])
        state = mix_columns(state, inv=True)
        state = shift_rows(state, inv=True)
        state = sub_bytes(state, inv=True)
    
    # Round 0 inverso
    state = add_round_key(state, round_keys[0])
    
    return bytes(state)

# ============================================================================
# PADDING (PKCS#7)
# ============================================================================

def pkcs7_pad(data, block_size=16):
    """Adiciona padding PKCS#7"""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data):
    """Remove padding PKCS#7"""
    padding_len = data[-1]
    if padding_len > 16 or padding_len == 0:
        raise ValueError("Padding inválido")
    return data[:-padding_len]

# ============================================================================
# MODOS DE OPERAÇÃO
# ============================================================================

def aes_ecb_encrypt(data, key):
    """AES-128 ECB mode"""
    round_keys = key_expansion(key)
    padded = pkcs7_pad(data)
    
    ciphertext = bytearray()
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        encrypted = aes_encrypt_bloco(block, round_keys)
        ciphertext.extend(encrypted)
    
    return bytes(ciphertext)

def aes_ecb_decrypt(data, key):
    """AES-128 ECB mode decryption"""
    round_keys = key_expansion(key)
    
    if len(data) % 16 != 0:
        raise ValueError("Dados cifrados têm tamanho inválido")
    
    plaintext_padded = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted = aes_decrypt_bloco(block, round_keys)
        plaintext_padded.extend(decrypted)
    
    return pkcs7_unpad(bytes(plaintext_padded))

def aes_cbc_encrypt(data, key, iv):
    """AES-128 CBC mode com IV"""
    round_keys = key_expansion(key)
    padded = pkcs7_pad(data)
    
    ciphertext = bytearray()
    previous = iv
    
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        # XOR com bloco anterior (ou IV)
        xored = bytes([block[j] ^ previous[j] for j in range(16)])
        encrypted = aes_encrypt_bloco(xored, round_keys)
        ciphertext.extend(encrypted)
        previous = encrypted
    
    return bytes(ciphertext)

def aes_cbc_decrypt(data, key, iv):
    """AES-128 CBC mode decryption"""
    round_keys = key_expansion(key)
    
    if len(data) % 16 != 0:
        raise ValueError("Dados cifrados têm tamanho inválido")
    
    plaintext_padded = bytearray()
    previous = iv
    
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted = aes_decrypt_bloco(block, round_keys)
        # XOR com bloco anterior (ou IV)
        xored = bytes([decrypted[j] ^ previous[j] for j in range(16)])
        plaintext_padded.extend(xored)
        previous = block
    
    return pkcs7_unpad(bytes(plaintext_padded))

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

def bytes_to_hex(b):
    """Converte bytes para string hexadecimal"""
    return ''.join(f'{byte:02x}' for byte in b)

def hex_to_bytes(h):
    """Converte string hexadecimal para bytes"""
    return bytes(int(h[i:i+2], 16) for i in range(0, len(h), 2))

def gerar_chave_aleatoria():
    """Gera uma chave AES-128 aleatória"""
    import random
    return bytes([random.randint(0, 255) for _ in range(16)])

def gerar_iv_aleatorio():
    """Gera um IV aleatório de 16 bytes"""
    import random
    return bytes([random.randint(0, 255) for _ in range(16)])

# ============================================================================
# TESTE E DEMONSTRAÇÃO
# ============================================================================

def testar_aes():
    print("=" * 70)
    print("        AES-128 IMPLEMENTAÇÃO MANUAL - TESTE DE VALIDAÇÃO")
    print("=" * 70)
    
    # Vetores de teste NIST
    chave = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
    
    plaintext = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    
    expected_cipher = bytes([0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                             0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a])
    
    print(f"\n📋 VETOR DE TESTE NIST:")
    print(f"   Chave:       {bytes_to_hex(chave)}")
    print(f"   Plaintext:   {bytes_to_hex(plaintext)}")
    print(f"   Esperado:    {bytes_to_hex(expected_cipher)}")
    
    round_keys = key_expansion(chave)
    ciphertext = aes_encrypt_bloco(plaintext, round_keys)
    decrypted = aes_decrypt_bloco(ciphertext, round_keys)
    
    print(f"\n🔐 RESULTADO:")
    print(f"   Ciphertext:  {bytes_to_hex(ciphertext)}")
    print(f"   Decrypted:   {bytes_to_hex(decrypted)}")
    
    if ciphertext == expected_cipher:
        print("   ✅ TESTE ECB PASSED - Ciphertext coincide com NIST")
    else:
        print("   ❌ TESTE ECB FAILED")
    
    if decrypted == plaintext:
        print("   ✅ TESTE DECRYPT PASSED - Decifragem correta")
    else:
        print("   ❌ TESTE DECRYPT FAILED")

def testar_modos():
    print("\n" + "=" * 70)
    print("              TESTE DE MODOS DE OPERAÇÃO")
    print("=" * 70)
    
    chave = gerar_chave_aleatoria()
    iv = gerar_iv_aleatorio()
    
    mensagem = b"Esta e uma mensagem secreta que sera cifrada com AES-128 implementado manualmente!"
    
    print(f"\n📝 MENSAGEM ORIGINAL ({len(mensagem)} bytes):")
    print(f"   {mensagem.decode('utf-8')}")
    print(f"\n🔑 Chave: {bytes_to_hex(chave)[:32]}...")
    print(f"🔑 IV:    {bytes_to_hex(iv)}")
    
    # Teste ECB
    print("\n" + "-" * 50)
    print("📦 MODO ECB (Electronic Codebook)")
    ecb_cipher = aes_ecb_encrypt(mensagem, chave)
    ecb_plain = aes_ecb_decrypt(ecb_cipher, chave)
    print(f"   Ciphertext ({len(ecb_cipher)} bytes): {bytes_to_hex(ecb_cipher)[:64]}...")
    print(f"   Decrypted: {ecb_plain.decode('utf-8')[:60]}...")
    print(f"   ✅ ECB {'PASSED' if ecb_plain == mensagem else 'FAILED'}")
    
    # Teste CBC
    print("\n" + "-" * 50)
    print("📦 MODO CBC (Cipher Block Chaining)")
    cbc_cipher = aes_cbc_encrypt(mensagem, chave, iv)
    cbc_plain = aes_cbc_decrypt(cbc_cipher, chave, iv)
    print(f"   Ciphertext ({len(cbc_cipher)} bytes): {bytes_to_hex(cbc_cipher)[:64]}...")
    print(f"   Decrypted: {cbc_plain.decode('utf-8')[:60]}...")
    print(f"   ✅ CBC {'PASSED' if cbc_plain == mensagem else 'FAILED'}")
    
    # Teste de avalanche (mudança de 1 bit no plaintext)
    print("\n" + "-" * 50)
    print("🏔️ TESTE DE AVALANCHE (mudança de 1 bit)")
    msg2 = bytearray(mensagem)
    msg2[0] ^= 0x01  # flip primeiro bit
    msg2 = bytes(msg2)
    
    cbc_cipher2 = aes_cbc_encrypt(msg2, chave, iv)
    
    # Contar bits diferentes entre os dois ciphertexts
    diff_bits = 0
    for i in range(min(len(cbc_cipher), len(cbc_cipher2))):
        xor_val = cbc_cipher[i] ^ cbc_cipher2[i]
        diff_bits += bin(xor_val).count('1')
    
    diff_percent = (diff_bits / (len(cbc_cipher) * 8)) * 100
    print(f"   Bits diferentes: {diff_bits} / {len(cbc_cipher) * 8} ({diff_percent:.1f}%)")
    print(f"   ✅ Avalanche {'OK' if diff_percent > 40 else 'POUCO'} - Esperado ~50%")

def benchmark():
    print("\n" + "=" * 70)
    print("              BENCHMARK DE PERFORMANCE")
    print("=" * 70)
    
    import time
    
    chave = gerar_chave_aleatoria()
    dados = b"X" * 1024 * 1024  # 1MB
    
    print(f"\n📊 Cifrando 1MB com AES-128 CBC...")
    
    start = time.time()
    cipher = aes_cbc_encrypt(dados, chave, gerar_iv_aleatorio())
    encrypt_time = time.time() - start
    
    start = time.time()
    plain = aes_cbc_decrypt(cipher, chave, gerar_iv_aleatorio())
    decrypt_time = time.time() - start
    
    print(f"   ⚡ Criptografia: {encrypt_time:.3f} segundos")
    print(f"   ⚡ Decriptografia: {decrypt_time:.3f} segundos")
    print(f"   📈 Throughput: {1024 / encrypt_time:.1f} KB/s cifra")
    
    if plain == dados:
        print("   ✅ Verificação de integridade OK")

# ============================================================================
# INTERFACE PRINCIPAL
# ============================================================================

def main():
    print("=" * 70)
    print("     AES-128 IMPLEMENTAÇÃO MANUAL - RIJNDAEL DO ZERO")
    print("     Sem bibliotecas - apenas matemática GF(2^8)")
    print("=" * 70)
    
    while True:
        print("\n" + "-" * 50)
        print("[1] Teste vetor NIST")
        print("[2] Teste ECB/CBC")
        print("[3] Benchmark 1MB")
        print("[4] Cifrar mensagem personalizada")
        print("[5] Sair")
        print("-" * 50)
        
        op = input("Opção: ").strip()
        
        if op == "1":
            testar_aes()
        
        elif op == "2":
            testar_modos()
        
        elif op == "3":
            benchmark()
        
        elif op == "4":
            print("\n📝 MENSAGEM PERSONALIZADA")
            msg = input("Texto a cifrar: ").encode('utf-8')
            modo = input("Modo (ecb/cbc) [padrão cbc]: ").strip().lower() or "cbc"
            
            chave = hex_to_bytes(input("Chave (32 hex, 16 bytes) [ENTER gera aleatória]: ").strip())
            if len(chave) != 16:
                chave = gerar_chave_aleatoria()
                print(f"   Chave gerada: {bytes_to_hex(chave)}")
            
            if modo == "cbc":
                iv = hex_to_bytes(input("IV (32 hex) [ENTER aleatório]: ").strip())
                if len(iv) != 16:
                    iv = gerar_iv_aleatorio()
                    print(f"   IV gerado: {bytes_to_hex(iv)}")
                cipher = aes_cbc_encrypt(msg, chave, iv)
                plain = aes_cbc_decrypt(cipher, chave, iv)
            else:
                cipher = aes_ecb_encrypt(msg, chave)
                plain = aes_ecb_decrypt(cipher, chave)
            
            print(f"\n🔐 Ciphertext: {bytes_to_hex(cipher)}")
            print(f"📄 Decifrado: {plain.decode('utf-8')}")
            print(f"✅ {'CORRETO' if plain == msg else 'FALHA NA INTEGRIDADE'}")
        
        elif op == "5":
            print("\n🔒 Encerrando...")
            break
        
        else:
            print("Opção inválida")

if __name__ == "__main__":
    main()