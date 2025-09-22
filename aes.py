# aes.py
# Exemplo de uso na linha de comando:
# Para cifrar:   python aes.py -enc arquivo_original.txt -out arquivo_cifrado.bin senha123
# Para decifrar: python aes.py -dec arquivo_cifrado.bin -out arquivo_decifrado.txt senha123
# Aluno: Hellian Sampaio Silva Peixinho - Engenharia da Computação - UNIVASF
# Agradecimento/Referencia a https://gist.github.com/SpotlightKid/53e1eb408267315de620

import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2 # derivação da chave a partir da senha

# Configurações globais
ITERACOES = 100000
TAMANHO_CHAVE = 32  # AES-256
TAMANHO_SAL = 16 # valor aleatório adicionado à senha para aumentar a segurança
TAMANHO_IV = 16 #tamanho do vetor de inicialização

# Deriva a chave com PBKDF2
def derivar_chave(senha, sal):
    return PBKDF2(senha, sal, dkLen=TAMANHO_CHAVE, count=ITERACOES)

# Cifra o arquivo
def cifrar(arquivo_entrada, arquivo_saida, senha):
    sal = get_random_bytes(TAMANHO_SAL)
    iv = get_random_bytes(TAMANHO_IV)
    chave = derivar_chave(senha.encode(), sal)

    cifra = AES.new(chave, AES.MODE_CBC, iv)

    with open(arquivo_entrada, "rb") as f:
        dados = f.read()

    # padding PKCS7
    padding = 16 - (len(dados) % 16)
    dados += bytes([padding]) * padding

    dados_cifrados = cifra.encrypt(dados)

    # Estrutura: SAL + IV + Dados
    with open(arquivo_saida, "wb") as f:
        f.write(sal + iv + dados_cifrados)

    print(f" Arquivo cifrado salvo em '{arquivo_saida}'")

# Decifra o arquivo
def decifrar(arquivo_entrada, arquivo_saida, senha):
    with open(arquivo_entrada, "rb") as f:
        conteudo = f.read()

    sal = conteudo[:TAMANHO_SAL]
    iv = conteudo[TAMANHO_SAL:TAMANHO_SAL+TAMANHO_IV]
    dados_cifrados = conteudo[TAMANHO_SAL+TAMANHO_IV:]

    chave = derivar_chave(senha.encode(), sal)

    cifra = AES.new(chave, AES.MODE_CBC, iv)
    dados = cifra.decrypt(dados_cifrados)

    # Remove PKCS7 padding
    padding = dados[-1]
    dados = dados[:-padding]

    with open(arquivo_saida, "wb") as f:
        f.write(dados)

    print(f" Arquivo decifrado salvo em '{arquivo_saida}'")

# Função principal
def main():
    if len(sys.argv) != 6 or sys.argv[1] not in ['-enc', '-dec'] or sys.argv[3] != '-out':
        print("Método de Uso via console")
        print("  python aes.py -enc arquivo_entrada.txt -out arquivo_saida.bin senha123")
        print("  python aes.py -dec arquivo_entrada.bin -out arquivo_saida.txt senha123")
        sys.exit(1)

    modo = sys.argv[1]
    arquivo_entrada = sys.argv[2]
    arquivo_saida = sys.argv[4]
    senha = sys.argv[5]

    if modo == '-enc':
        cifrar(arquivo_entrada, arquivo_saida, senha)
    else:
        decifrar(arquivo_entrada, arquivo_saida, senha)

if __name__ == "__main__":
    main()
