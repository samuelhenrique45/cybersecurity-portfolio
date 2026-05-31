import hashlib
import hmac
import secrets
import time
import json
import os
import re
import bcrypt
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from collections import defaultdict
import threading

# ============================================================================
# CONFIGURAÇÃO DE SEGURANÇA AVANÇADA
# ============================================================================

DB_FILE = "usuarios.enc"
KEY_FILE = "key.key"
LOG_FILE = "auth.log"
BLOCKED_IPS_FILE = "blocked_ips.json"

MAX_TENTATIVAS = 5
BLOQUEIO_SEGUNDOS = 300  # 5 minutos
BLOQUEIO_PERMANENTE_APOS = 10  # bloqueia permanentemente após 10 falhas em 1h
SENHA_MIN_LEN = 12
REQUER_MAIUSCULA = True
REQUER_MINUSCULA = True
REQUER_NUMERO = True
REQUER_SIMBOLO = True
SESSOES_MAX_POR_USUARIO = 3
TOKEN_EXPIRACAO_SEGUNDOS = 3600
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW = 60  # segundos

# ============================================================================
# INICIALIZAÇÃO CRIPTOGRÁFICA
# ============================================================================

def init_crypto():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    with open(KEY_FILE, 'rb') as f:
        return Fernet(f.read())

cipher = init_crypto()

# ============================================================================
# SISTEMA DE LOGGING
# ============================================================================

log_lock = threading.Lock()

def log_event(event_type, usuario, ip, detalhes=""):
    with log_lock:
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'user': usuario,
            'ip': ip,
            'details': detalhes
        }
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except:
            pass

# ============================================================================
# BLOQUEIO DE IP
# ============================================================================

def carregar_ips_bloqueados():
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, 'r') as f:
            return json.load(f)
    return {}

def salvar_ips_bloqueados(blocked):
    with open(BLOCKED_IPS_FILE, 'w') as f:
        json.dump(blocked, f, indent=2)

def ip_bloqueado(ip):
    blocked = carregar_ips_bloqueados()
    if ip in blocked:
        if time.time() < blocked[ip]:
            return True
        else:
            del blocked[ip]
            salvar_ips_bloqueados(blocked)
    return False

def bloquear_ip(ip, segundos=3600):
    blocked = carregar_ips_bloqueados()
    blocked[ip] = time.time() + segundos
    salvar_ips_bloqueados(blocked)
    log_event("IP_BLOCKED", "system", ip, f"Bloqueado por {segundos}s")

# ============================================================================
# RATE LIMITING
# ============================================================================

rate_limits = defaultdict(list)
rate_lock = threading.Lock()

def check_rate_limit(ip):
    with rate_lock:
        now = time.time()
        rate_limits[ip] = [t for t in rate_limits[ip] if now - t < RATE_LIMIT_WINDOW]
        
        if len(rate_limits[ip]) >= RATE_LIMIT_REQUESTS:
            return False
        rate_limits[ip].append(now)
        return True

# ============================================================================
# VALIDAÇÃO DE SENHA FORTE
# ============================================================================

def validar_senha_forte(senha):
    feedback = []
    
    if len(senha) < SENHA_MIN_LEN:
        feedback.append(f"Mínimo {SENHA_MIN_LEN} caracteres")
    
    if REQUER_MAIUSCULA and not re.search(r"[A-Z]", senha):
        feedback.append("Pelo menos 1 letra maiúscula")
    
    if REQUER_MINUSCULA and not re.search(r"[a-z]", senha):
        feedback.append("Pelo menos 1 letra minúscula")
    
    if REQUER_NUMERO and not re.search(r"[0-9]", senha):
        feedback.append("Pelo menos 1 número")
    
    if REQUER_SIMBOLO and not re.search(r"[!@#$%^&*()_+\-=\[\]{};:,.<>?/\\|`~]", senha):
        feedback.append("Pelo menos 1 símbolo especial")
    
    if re.search(r"(.)\1{2,}", senha):
        feedback.append("Evite caracteres repetidos consecutivamente")
    
    if senha.lower() in open('/usr/share/wordlists/rockyou.txt', encoding='latin-1').read() if os.path.exists('/usr/share/wordlists/rockyou.txt') else ['password', '123456', 'admin']:
        feedback.append("Senha está em lista de senhas comuns")
    
    return len(feedback) == 0, feedback

# ============================================================================
# HASH DE SENHA COM BCRYPT + ARGON2 FALLBACK
# ============================================================================

def hash_senha_avancado(senha):
    try:
        salt = bcrypt.gensalt(rounds=12)
        hash_bytes = bcrypt.hashpw(senha.encode('utf-8'), salt)
        return 'bcrypt:' + hash_bytes.decode('utf-8')
    except:
        # Fallback para PBKDF2
        salt = secrets.token_hex(32)
        hash_ = hashlib.pbkdf2_hmac('sha512', senha.encode(), salt.encode(), 600000)
        return f'pbkdf2:{salt}:{hash_.hex()}'

def verificar_senha_avancado(senha, hash_armazenado):
    if hash_armazenado.startswith('bcrypt:'):
        hash_bytes = hash_armazenado[7:].encode('utf-8')
        return bcrypt.checkpw(senha.encode('utf-8'), hash_bytes)
    elif hash_armazenado.startswith('pbkdf2:'):
        _, salt, hash_hex = hash_armazenado.split(':')
        hash_calc = hashlib.pbkdf2_hmac('sha512', senha.encode(), salt.encode(), 600000).hex()
        return hmac.compare_digest(hash_calc, hash_hex)
    return False

# ============================================================================
# TOKEN DE SESSÃO
# ============================================================================

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.session_lock = threading.Lock()
    
    def criar_sessao(self, usuario, ip, user_agent):
        token = secrets.token_urlsafe(64)
        with self.session_lock:
            # Limpar sessões antigas do usuário
            user_sessions = [k for k,v in self.sessions.items() if v['usuario'] == usuario]
            if len(user_sessions) >= SESSOES_MAX_POR_USUARIO:
                # Remove a mais antiga
                oldest = min(user_sessions, key=lambda x: self.sessions[x]['criado_em'])
                del self.sessions[oldest]
            
            self.sessions[token] = {
                'usuario': usuario,
                'ip': ip,
                'user_agent': user_agent,
                'criado_em': time.time(),
                'ultimo_acesso': time.time()
            }
        return token
    
    def validar_sessao(self, token, ip, user_agent):
        with self.session_lock:
            if token not in self.sessions:
                return None
            
            sessao = self.sessions[token]
            
            # Expiração por tempo
            if time.time() - sessao['criado_em'] > TOKEN_EXPIRACAO_SEGUNDOS:
                del self.sessions[token]
                return None
            
            # Verificar IP (opcional, pode ser desativado)
            if sessao['ip'] != ip:
                return None
            
            sessao['ultimo_acesso'] = time.time()
            return sessao['usuario']
    
    def invalidar_sessao(self, token):
        with self.session_lock:
            if token in self.sessions:
                del self.sessions[token]
                return True
        return False
    
    def listar_sessoes(self, usuario):
        with self.session_lock:
            return [{'token': k, **v} for k,v in self.sessions.items() if v['usuario'] == usuario]

session_manager = SessionManager()

# ============================================================================
# BANCO DE DADOS CRIPTOGRAFADO
# ============================================================================

def carregar_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'rb') as f:
                encrypted = f.read()
                decrypted = cipher.decrypt(encrypted)
                return json.loads(decrypted.decode())
        except:
            return {}
    return {}

def salvar_db(db):
    data = json.dumps(db, indent=2).encode()
    encrypted = cipher.encrypt(data)
    with open(DB_FILE, 'wb') as f:
        f.write(encrypted)

# ============================================================================
# 2FA TOTP SIMPLIFICADO
# ============================================================================

def gerar_2fa_secret():
    return secrets.token_hex(20)

def verificar_2fa(secret, codigo):
    # TOTP simplificado - em produção usar pyotp
    import base64
    import hmac
    import struct
    
    if not secret or not codigo:
        return False
    
    try:
        codigo_int = int(codigo)
        for offset in [-1, 0, 1]:
            counter = int((time.time() + offset * 30) // 30)
            key = base64.b32encode(secret.encode())
            h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
            o = h[-1] & 0x0f
            code = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
            if code == codigo_int:
                return True
        return False
    except:
        return False

# ============================================================================
# REGISTRO DE USUÁRIO
# ============================================================================

def registrar(usuario, senha, email, ip):
    # Validações prévias
    if not re.match(r'^[a-zA-Z0-9_.-]{3,32}$', usuario):
        return False, "Usuário deve ter 3-32 caracteres alfanuméricos, _, . ou -"
    
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return False, "Email inválido"
    
    valido, feedback = validar_senha_forte(senha)
    if not valido:
        return False, "Senha fraca: " + ", ".join(feedback)
    
    db = carregar_db()
    if usuario in db:
        log_event("REGISTER_FAIL", usuario, ip, "Usuário já existe")
        return False, "Usuário já existe"
    
    hash_senha = hash_senha_avancado(senha)
    twofa_secret = gerar_2fa_secret()
    
    db[usuario] = {
        "hash": hash_senha,
        "email": email,
        "2fa_secret": twofa_secret,
        "2fa_ativado": False,
        "tentativas": 0,
        "falhas_consecutivas": 0,
        "bloqueado_ate": 0,
        "criado_em": datetime.now().isoformat(),
        "criado_de_ip": ip,
        "ultimo_login": None,
        "ultimo_ip": None,
        "historico_ips": [],
        "roles": ["user"]
    }
    
    salvar_db(db)
    log_event("REGISTER_SUCCESS", usuario, ip, f"Email: {email}")
    return True, "Cadastro realizado! Ative o 2FA nas configurações."

# ============================================================================
# LOGIN PRINCIPAL
# ============================================================================

def login(usuario, senha, ip, user_agent, twofa_code=None):
    # Rate limiting por IP
    if not check_rate_limit(ip):
        log_event("RATE_LIMIT", usuario, ip, "Rate limit exceeded")
        return False, "Muitas requisições. Aguarde 60 segundos."
    
    # Verificar bloqueio de IP
    if ip_bloqueado(ip):
        return False, "IP bloqueado por atividades suspeitas"
    
    db = carregar_db()
    
    if usuario not in db:
        log_event("LOGIN_FAIL_NOUSER", usuario, ip, "Usuário não existe")
        time.sleep(secrets.randbelow(3) + 1)  # Timing attack mitigation
        return False, "Usuário ou senha inválidos"
    
    dados = db[usuario]
    
    # Verificar bloqueio da conta
    if time.time() < dados["bloqueado_ate"]:
        restante = int(dados["bloqueado_ate"] - time.time())
        log_event("LOGIN_BLOCKED", usuario, ip, f"Conta bloqueada por {restante}s")
        return False, f"Conta bloqueada. Aguarde {restante} segundos."
    
    # Verificar senha
    senha_valida = verificar_senha_avancado(senha, dados["hash"])
    
    if not senha_valida:
        dados["tentativas"] = dados.get("tentativas", 0) + 1
        dados["falhas_consecutivas"] = dados.get("falhas_consecutivas", 0) + 1
        
        # Bloqueio progressivo
        if dados["falhas_consecutivas"] >= BLOQUEIO_PERMANENTE_APOS:
            dados["bloqueado_ate"] = time.time() + 86400  # 24h
            log_event("PERMANENT_BLOCK", usuario, ip, "Bloqueado por múltiplas falhas")
            salvar_db(db)
            return False, "Conta bloqueada por 24 horas devido a múltiplas tentativas."
        
        if dados["tentativas"] >= MAX_TENTATIVAS:
            dados["bloqueado_ate"] = time.time() + BLOQUEIO_SEGUNDOS
            dados["tentativas"] = 0
            log_event("TEMPORARY_BLOCK", usuario, ip, f"Bloqueado por {BLOQUEIO_SEGUNDOS}s")
            salvar_db(db)
            return False, f"Muitas tentativas. Conta bloqueada por {BLOQUEIO_SEGUNDOS} segundos."
        
        salvar_db(db)
        restantes = MAX_TENTATIVAS - dados["tentativas"]
        log_event("LOGIN_FAIL_PASSWORD", usuario, ip, f"Tentativas restantes: {restantes}")
        return False, f"Senha incorreta. {restantes} tentativa(s) restantes."
    
    # Verificar 2FA se ativado
    if dados.get("2fa_ativado", False):
        if not twofa_code:
            return False, "Código 2FA necessário", "2FA_REQUIRED"
        
        if not verificar_2fa(dados["2fa_secret"], twofa_code):
            log_event("LOGIN_FAIL_2FA", usuario, ip, "Código 2FA inválido")
            return False, "Código 2FA inválido"
    
    # Login bem-sucedido
    dados["tentativas"] = 0
    dados["falhas_consecutivas"] = 0
    dados["ultimo_login"] = datetime.now().isoformat()
    dados["ultimo_ip"] = ip
    if len(dados.get("historico_ips", [])) > 50:
        dados["historico_ips"] = dados["historico_ips"][-50:]
    dados.setdefault("historico_ips", []).append(ip)
    
    salvar_db(db)
    
    # Criar sessão
    token = session_manager.criar_sessao(usuario, ip, user_agent)
    
    log_event("LOGIN_SUCCESS", usuario, ip, f"Sessão criada: {token[:16]}...")
    return True, "Login realizado!", token

# ============================================================================
# LOGOUT
# ============================================================================

def logout(token, ip):
    usuario = session_manager.validar_sessao(token, ip, "")
    if usuario:
        session_manager.invalidar_sessao(token)
        log_event("LOGOUT", usuario, ip, "Sessão encerrada")
        return True, "Logout realizado"
    return False, "Sessão inválida"

# ============================================================================
# GERENCIAMENTO DE PERFIL
# ============================================================================

def alterar_senha(usuario, senha_atual, nova_senha, ip):
    db = carregar_db()
    
    if usuario not in db:
        return False, "Usuário não encontrado"
    
    dados = db[usuario]
    
    if not verificar_senha_avancado(senha_atual, dados["hash"]):
        log_event("PASSWORD_CHANGE_FAIL", usuario, ip, "Senha atual incorreta")
        return False, "Senha atual incorreta"
    
    valido, feedback = validar_senha_forte(nova_senha)
    if not valido:
        return False, "Nova senha fraca: " + ", ".join(feedback)
    
    if senha_atual == nova_senha:
        return False, "Nova senha deve ser diferente da atual"
    
    dados["hash"] = hash_senha_avancado(nova_senha)
    dados["senha_alterada_em"] = datetime.now().isoformat()
    
    # Invalidar todas as sessões
    for sess_token in session_manager.sessions.copy():
        if session_manager.sessions.get(sess_token, {}).get('usuario') == usuario:
            session_manager.invalidar_sessao(sess_token)
    
    salvar_db(db)
    log_event("PASSWORD_CHANGE_SUCCESS", usuario, ip, "Senha alterada com sucesso")
    return True, "Senha alterada! Todas as sessões foram invalidadas."

def ativar_2fa(usuario, ip):
    db = carregar_db()
    if usuario not in db:
        return False, "Usuário não encontrado"
    
    dados = db[usuario]
    dados["2fa_ativado"] = True
    salvar_db(db)
    log_event("2FA_ENABLED", usuario, ip, "2FA ativado")
    return True, f"2FA ativado! Secret: {dados['2fa_secret']}"

def desativar_2fa(usuario, senha, ip):
    db = carregar_db()
    if usuario not in db:
        return False, "Usuário não encontrado"
    
    dados = db[usuario]
    
    if not verificar_senha_avancado(senha, dados["hash"]):
        log_event("2FA_DISABLE_FAIL", usuario, ip, "Senha incorreta")
        return False, "Senha incorreta"
    
    dados["2fa_ativado"] = False
    salvar_db(db)
    log_event("2FA_DISABLED", usuario, ip, "2FA desativado")
    return True, "2FA desativado"

# ============================================================================
# INTERFACE PRINCIPAL
# ============================================================================

def obter_ip():
    # Simulação - em produção, obter do request
    return "127.0.0.1"

def obter_user_agent():
    return "Terminal/1.0"

def main():
    print("=" * 65)
    print("     🛡️  SISTEMA DE LOGIN ULTRA SEGURO v4.0  🛡️")
    print("     PBKDF2-SHA512 + bcrypt | 2FA | Rate Limiting")
    print("=" * 65)
    
    sessoes_ativas = {}
    
    while True:
        print("\n" + "-" * 65)
        print("[1] Registrar  [2] Login  [3] Listar Sessões  [4] Alterar Senha")
        print("[5] Ativar 2FA  [6] Desativar 2FA  [7] Logout  [8] Sair")
        print("-" * 65)
        op = input("Opção: ").strip()
        
        ip = obter_ip()
        ua = obter_user_agent()
        
        if op == "1":
            user = input("Usuário (3-32 chars): ").strip()
            pwd = input("Senha: ").strip()
            email = input("Email: ").strip()
            ok, msg = registrar(user, pwd, email, ip)
            print(f"\n{msg}")
            
            if ok:
                print("\n📌 REQUISITOS DE SENHA:")
                print(f"   • Mínimo {SENHA_MIN_LEN} caracteres")
                print("   • Maiúsculas, minúsculas, números, símbolos")
                print("   • Evite repetições e palavras comuns")
        
        elif op == "2":
            user = input("Usuário: ").strip()
            pwd = input("Senha: ").strip()
            
            result = login(user, pwd, ip, ua)
            
            if len(result) == 3:
                # 2FA necessário
                ok, msg, _ = result
                if msg == "Código 2FA necessário":
                    code = input("Código 2FA: ").strip()
                    ok, msg, token = login(user, pwd, ip, ua, code)
                    if ok:
                        sessoes_ativas[token] = user
                        print(f"\n✅ {msg}")
                        print(f"🔑 Token: {token[:32]}...")
                    else:
                        print(f"\n{msg}")
            else:
                ok, msg = result
                if ok:
                    # login sem 2FA
                    print(f"\n✅ {msg}")
                else:
                    print(f"\n{msg}")
        
        elif op == "3":
            print("\n📋 SESSÕES ATIVAS:")
            for token, info in session_manager.sessions.items():
                if 'usuario' in info:
                    print(f"   • {info['usuario']} - Criado: {datetime.fromtimestamp(info['criado_em']).strftime('%H:%M:%S')}")
        
        elif op == "4":
            user = input("Usuário: ").strip()
            old = input("Senha atual: ").strip()
            new = input("Nova senha: ").strip()
            ok, msg = alterar_senha(user, old, new, ip)
            print(f"\n{msg}")
        
        elif op == "5":
            user = input("Usuário: ").strip()
            ok, msg = ativar_2fa(user, ip)
    