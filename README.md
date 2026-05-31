🔐 Cybersecurity Portfolio
Projetos de segurança ofensiva e defensiva desenvolvidos do zero em Python puro.
Autor: Samuel Henrique
Idade: 13 anos
Foco: Criptografia · Segurança Defensiva · Forense Digital
📁 Projetos
01 · Analisador de Senhas
Analisa força de senhas com cálculo real de entropia em bits, detecção de padrões fracos (sequências de teclado, palavras comuns), estimativa de tempo para quebra por força bruta e gerador de senhas seguras com secrets.
Conceitos: Entropia de Shannon, regex, análise estatística
02 · Scanner de Portas
Scanner TCP multi-threaded com banner grabbing, identificação de serviços (150+ portas mapeadas), detecção de SO via TTL e exportação de relatório em JSON.
Conceitos: Sockets, threading, protocolos de rede
03 · Sistema de Login Seguro
Sistema de autenticação com bcrypt (12 rounds), banco de dados criptografado com Fernet, 2FA TOTP, rate limiting por IP, bloqueio progressivo contra brute force e gerenciamento de sessões com tokens.
Conceitos: bcrypt, PBKDF2-SHA512, HMAC, JWT-like tokens
04 · AES-128 Manual
Implementação completa do algoritmo Rijndael do zero, sem bibliotecas criptográficas. Inclui multiplicação em campo de Galois GF(2^8), todos os 10 rounds, modos ECB e CBC, padding PKCS#7 e validação contra vetores de teste NIST.
Conceitos: GF(2^8), SubBytes, ShiftRows, MixColumns, KeySchedule
05 · Sistema de Detecção de Intrusão (IDS)
IDS em tempo real que monitora logs de SSH, Apache e Nginx. Detecta SQL Injection, XSS, Command Injection, Path Traversal, brute force e DDoS. Auto-bloqueia IPs suspeitos e gera relatórios detalhados.
Conceitos: Regex, threading, análise de logs, detecção de anomalias
06 · CTF — Capture The Flag
Plataforma CTF completa com 16 desafios em 6 categorias: Criptografia (César, Base64, XOR), Hashing (MD5, SHA1), Esteganografia (LSB), Forense, Reverse Engineering e Web (SQLi, XSS). Sistema de pontuação, ranking e dicas.
Conceitos: Criptografia clássica, hashing, web security, engenharia reversa
07 · RSA e ECC do Zero
Implementação completa de RSA (Miller-Rabin, Euclidiano Estendido, assinatura digital) e ECC com a curva secp256k1 — a mesma usada pelo Bitcoin. Inclui ECDH para acordo de chaves e ECDSA para assinatura digital.
Conceitos: Aritmética modular, curvas elípticas, GF(p), ECDH, ECDSA
08 · Forense Digital
Toolkit forense com identificação de arquivos por magic bytes, file carving para recuperação de dados deletados, análise de dumps de memória, parser de PCAP manual e verificação de integridade com hashes.
Conceitos: Magic bytes, file carving, análise de memória, PCAP
🛠️ Tecnologias
Python 3.10+
Sem dependências externas nos projetos de criptografia (implementação manual)
bcrypt, cryptography no sistema de login
threading, socket, struct, hashlib, re
⚠️ Aviso Legal
Todos os projetos foram desenvolvidos para fins educacionais.
Ferramentas de segurança ofensiva devem ser usadas apenas em ambientes próprios ou com autorização explícita.
📫 Contato
GitHub: @samuelhenrique45# cybersecurity-portfolio