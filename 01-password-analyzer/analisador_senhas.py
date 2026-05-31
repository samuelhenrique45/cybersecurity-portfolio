import re
import math
from collections import Counter

def calcular_entropia(senha):
    """Calcula entropia real da senha em bits"""
    tamanho = len(senha)
    
    # Conjuntos de caracteres
    conjuntos = {
        'minusculas': 26 if re.search(r'[a-z]', senha) else 0,
        'maiusculas': 26 if re.search(r'[A-Z]', senha) else 0,
        'numeros': 10 if re.search(r'[0-9]', senha) else 0,
        'simbolos': 32 if re.search(r'[!@#$%^&*()_+\-=\[\]{};:,.<>?/\\|`~]', senha) else 0,
        'espacos': 1 if ' ' in senha else 0,
        'unicode': 65536 if any(ord(c) > 127 for c in senha) else 0
    }
    
    espaco_caracteres = sum(conjuntos.values())
    if espaco_caracteres == 0:
        return 0.0
    
    entropia_bruta = tamanho * math.log2(espaco_caracteres) if espaco_caracteres > 0 else 0
    
    # Penalidade por repetição de caracteres
    freq = Counter(senha)
    repeticao_penalidade = 0
    for char, count in freq.items():
        if count > 1:
            repeticao_penalidade += math.log2(count)
    
    entropia_final = max(0, entropia_bruta - repeticao_penalidade)
    return round(entropia_final, 2)

def detectar_padroes_comuns(senha):
    """Detecta padrões fracos na senha"""
    padroes = []
    senha_lower = senha.lower()
    
    # Palavras comuns
    palavras_comuns = ['senha', 'password', '123456', 'admin', 'root', 'qwerty', 
                       'abc123', 'letmein', 'welcome', 'master', 'login', 'user']
    
    for palavra in palavras_comuns:
        if palavra in senha_lower:
            padroes.append(f"Contém palavra comum: '{palavra}'")
            break
    
    # Sequências do teclado
    teclado_linhas = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm']
    for linha in teclado_linhas:
        for i in range(len(linha) - 2):
            if linha[i:i+3] in senha_lower:
                padroes.append(f"Sequência de teclado: '{linha[i:i+3]}'")
                break
    
    # Sequências numéricas
    for i in range(10):
        seq = f"{i}{i+1}{i+2}"
        if seq in senha:
            padroes.append(f"Sequência numérica: '{seq}'")
            break
    
    # Letras repetidas (3x ou mais)
    for c in set(senha):
        if senha.count(c) >= 3:
            padroes.append(f"Caractere repetido: '{c}' ({senha.count(c)}x)")
            break
    
    # Caracteres consecutivos no alfabeto
    for i in range(ord('a'), ord('z') - 1):
        seq_abc = chr(i) + chr(i+1) + chr(i+2)
        if seq_abc in senha_lower:
            padroes.append(f"Sequência alfabética: '{seq_abc}'")
            break
    
    return padroes

def analisar_senha_avancada(senha):
    """Análise completa da senha"""
    pontos = 0
    feedback = []
    warnings = []
    
    # 1. Comprimento (peso 0-4)
    comprimento = len(senha)
    if comprimento >= 16:
        pontos += 4
        feedback.append("✅ Excelente comprimento (16+ caracteres)")
    elif comprimento >= 12:
        pontos += 3
        feedback.append("✅ Bom comprimento (12-15 caracteres)")
    elif comprimento >= 8:
        pontos += 1
        feedback.append("⚠️ Comprimento mínimo aceitável (8-11 caracteres)")
    else:
        feedback.append("❌ Muito curta (< 8 caracteres) - vulnerável a ataques de força bruta")
    
    # 2. Entropia
    entropia = calcular_entropia(senha)
    if entropia >= 60:
        pontos += 4
        feedback.append(f"✅ Entropia muito alta ({entropia} bits)")
    elif entropia >= 40:
        pontos += 3
        feedback.append(f"✅ Boa entropia ({entropia} bits)")
    elif entropia >= 25:
        pontos += 1
        feedback.append(f"⚠️ Entropia média ({entropia} bits)")
    else:
        feedback.append(f"❌ Entropia baixa ({entropia} bits) - fácil de quebrar")
    
    # 3. Diversidade de caracteres
    tem_maiuscula = bool(re.search(r"[A-Z]", senha))
    tem_minuscula = bool(re.search(r"[a-z]", senha))
    tem_numero = bool(re.search(r"[0-9]", senha))
    tem_simbolo = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};:,.<>?/\\|`~]", senha))
    
    diversidade_score = 0
    if tem_maiuscula:
        diversidade_score += 1
    else:
        feedback.append("❌ Adicione letras MAIÚSCULAS (A-Z)")
    
    if tem_minuscula:
        diversidade_score += 1
    else:
        feedback.append("❌ Adicione letras minúsculas (a-z)")
    
    if tem_numero:
        diversidade_score += 1
    else:
        feedback.append("❌ Adicione NÚMEROS (0-9)")
    
    if tem_simbolo:
        diversidade_score += 1
        feedback.append("✅ Contém símbolos")
    else:
        feedback.append("⚠️ Considere adicionar SÍMBOLOS (!@#$%^&*)")
    
    pontos += diversidade_score
    
    # 4. Detectar padrões fracos
    padroes = detectar_padroes_comuns(senha)
    if padroes:
        pontos = max(0, pontos - len(padroes))
        for padrao in padroes:
            warnings.append(f"⚠️ {padrao}")
    
    # 5. Verificar repetição excessiva
    unique_chars = len(set(senha))
    if unique_chars < comprimento / 2:
        pontos -= 2
        feedback.append("❌ Muitos caracteres repetidos")
    
    # 6. Análise de força bruta
    tentativas_estimadas = 0
    if tem_maiuscula and tem_minuscula and tem_numero and tem_simbolo:
        espaco = 94  # todos ASCII imprimíveis
    elif tem_maiuscula and tem_minuscula and tem_numero:
        espaco = 62
    elif tem_maiuscula and tem_minuscula:
        espaco = 52
    else:
        espaco = 26 + (10 if tem_numero else 0)
    
    if espaco > 0 and comprimento > 0:
        tentativas_estimadas = espaco ** comprimento
    
    # 7. Classificação final
    niveis = [
        (0, "💀 Muito fraca - Quebrada em segundos"),
        (4, "⚠️ Fraca - Evite uso real"),
        (7, "📌 Média - Aceitável apenas para testes"),
        (10, "✅ Forte - Boa para uso geral"),
        (13, "🏆 Muito forte - Excelente segurança"),
        (16, "🔒 Paranoia total - Nível militar")
    ]
    
    nivel_atual = "❌ Sem classificação"
    for threshold, nome in niveis:
        if pontos >= threshold:
            nivel_atual = nome
    
    # 8. Tempo estimado de quebra (simulação)
    tempo_quebrar = "Indeterminado"
    if tentativas_estimadas > 0:
        tentativas_por_segundo = 10_000_000_000  # 10 bilhões/s (hardware moderno)
        segundos = tentativas_estimadas / tentativas_por_segundo
        if segundos < 60:
            tempo_quebrar = f"{segundos:.1f} segundos"
        elif segundos < 3600:
            tempo_quebrar = f"{segundos/60:.1f} minutos"
        elif segundos < 86400:
            tempo_quebrar = f"{segundos/3600:.1f} horas"
        elif segundos < 31536000:
            tempo_quebrar = f"{segundos/86400:.1f} dias"
        else:
            tempo_quebrar = f"{segundos/31536000:.1f} anos"
    
    # 9. Output
    print("=" * 70)
    print("            🔐 ANÁLISE AVANÇADA DE SENHA 🔐")
    print("=" * 70)
    print(f"\n📝 Senha: {'*' * comprimento}")
    print(f"📊 Comprimento: {comprimento} caracteres")
    print(f"🎲 Entropia: {entropia} bits")
    print(f"🔢 Caracteres únicos: {unique_chars}/{comprimento}")
    print(f"🎯 Pontuação: {pontos}/16")
    print(f"⭐ Nível: {nivel_atual}")
    print(f"⏱️ Tempo estimado de quebra: {tempo_quebrar}")
    
    if warnings:
        print("\n⚠️ ALERTAS DE SEGURANÇA:")
        for w in warnings:
            print(f"  {w}")
    
    if feedback:
        print("\n📋 RECOMENDAÇÕES:")
        recomendacoes_mostradas = 0
        for f in feedback:
            if "❌" in f or "⚠️" in f:
                print(f"  {f}")
                recomendacoes_mostradas += 1
        if recomendacoes_mostradas == 0:
            print("  ✅ Nenhuma recomendação necessária - senha excelente!")
    
    # 10. Sugestão de melhoria
    if pontos < 10:
        print("\n💡 SUGESTÃO DE SENHA FORTE:")
        import secrets
        import string
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        sugestao = ''.join(secrets.choice(chars) for _ in range(16))
        print(f"   Exemplo: {sugestao}")
    
    print("\n" + "=" * 70)
    
    return {
        'pontos': pontos,
        'entropia': entropia,
        'comprimento': comprimento,
        'diversidade': diversidade_score,
        'nivel': nivel_atual
    }

# Execução principal
if __name__ == "__main__":
    print("\n🔒 SISTEMA DE ANÁLISE DE SEGURANÇA DE SENHAS 🔒")
    print("-" * 50)
    senha = input("Digite uma senha para analisar: ")
    print()
    resultado = analisar_senha_avancada(senha)