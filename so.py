import os
import hashlib
import getpass
import json
import random
import string
import shutil
import subprocess

USUARIO_FILE = "Usuarios.txt"


def hash_password(password):
    salt = os.urandom(16)
    hashed_password = hashlib.sha512(salt + password.encode()).hexdigest()
    return hashed_password, salt


def SalvaUsuario(username, password):
    hashed_password, salt = hash_password(password)

    userData = {
        "username": username,
        "salt": salt.hex(),
        "password": hashed_password
    }
    with open(USUARIO_FILE, "a") as file:
        file.write(json.dumps(userData) + "\n")



def CarregaUsuario():
    if not os.path.exists(USUARIO_FILE):
        return []
    usuarios = []

    with open(USUARIO_FILE, 'r') as file:
        for line in file:
            usuarios.append(json.loads(line.strip()))
    return usuarios


def VerificaLogin(username, password):
    usuarios = CarregaUsuario()
    for user in usuarios:
        if user["username"] == username:
            salt = bytes.fromhex(user["salt"])
            hashed_password = hashlib.sha512(salt + password.encode()).hexdigest()
            if hashed_password == user["password"]:
                return True
    return False


def iniciar_shell():
    usuarios = CarregaUsuario()

    if not usuarios:
        print("Nenhum usuário encontrado. Vamos criar um novo usuário.")
        username = input("Digite um nome de usuário: ")
        password = getpass.getpass("Digite uma senha: ")
        SalvaUsuario(username, password)
        print("Usuário criado com sucesso!")
    else:
        print("Login")
        username = input("Digite seu nome de usuário: ")
        password = getpass.getpass("Digite sua senha: ")

        if VerificaLogin(username, password):
            print("Login realizado com sucesso!")
        else:
            print("Usuário ou senha incorretos. Tente novamente.")


def listar_diretorio(dir1=None):
    if dir1 is None or dir1.strip() == "":
        dir1 = os.getcwd()
    try:
        subprocess.run(["ls", dir1] if os.name != "nt" else ["dir", dir1], shell=True)
    except Exception as e:
        print(f"Erro ao listar diretório: {e}")


def criar_arquivo(caminho_arquivo):
    conteudo = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
    try:
        diretorio = os.path.dirname(caminho_arquivo)
        if diretorio and not os.path.exists(diretorio):
            os.makedirs(diretorio)
        with open(caminho_arquivo, 'w') as file:
            file.write(conteudo)
        print(f"Arquivo '{caminho_arquivo}' criado com sucesso.")
    except Exception as e:
        print(f"Erro ao criar arquivo: {e}")


def apagar_arquivo(caminho_arquivo):
    try:
        if os.path.exists(caminho_arquivo):
            os.remove(caminho_arquivo)
            print(f"Arquivo '{caminho_arquivo}' apagado com sucesso.")
        else:
            print(f"Arquivo '{caminho_arquivo}' não existe.")
    except Exception as e:
        print(f"Erro ao apagar arquivo: {e}")


def criar_diretorio(caminho_diretorio):
    try:
        os.makedirs(caminho_diretorio, exist_ok=True)
        print(f"Diretório '{caminho_diretorio}' criado com sucesso.")
    except Exception as e:
        print(f"Erro ao criar diretório: {e}")


def apagar_diretorio(caminho_diretorio, force=False):
    try:
        if force:
            shutil.rmtree(caminho_diretorio)
            print(f"Diretório '{caminho_diretorio}' e todo o seu conteúdo foram apagados.")
        else:
            os.rmdir(caminho_diretorio)
            print(f"Diretório '{caminho_diretorio}' apagado com sucesso.")
    except Exception as e:
        print(f"Erro ao apagar diretório: {e}")


def main():
    iniciar_shell()
    print("Bem-vindo ao gerenciador de comandos! Digite 'sair' para encerrar.")

    while True:
        comando = input("\nDigite um comando: ").strip()

        if comando.startswith("listar"):
            partes = comando.split()
            if len(partes) == 1:
                listar_diretorio()
            else:
                listar_diretorio(partes[1])

        elif comando.startswith("criar arquivo"):
            partes = comando.split(maxsplit=2)
            if len(partes) < 3:
                print("Erro: Caminho do arquivo não especificado.")
            else:
                criar_arquivo(partes[2])

        elif comando.startswith("apagar arquivo"):
            partes = comando.split(maxsplit=2)
            if len(partes) < 3:
                print("Erro: Caminho do arquivo não especificado.")
            else:
                apagar_arquivo(partes[2])

        elif comando.startswith("criar diretorio"):
            partes = comando.split(maxsplit=2)
            if len(partes) < 3:
                print("Erro: Caminho do diretório não especificado.")
            else:
                criar_diretorio(partes[2])

        elif comando.startswith("apagar diretorio"):
            partes = comando.split(maxsplit=3)
            if len(partes) < 3:
                print("Erro: Caminho do diretório não especificado.")
            else:
                force = len(partes) == 4 and partes[3] == "--force"
                apagar_diretorio(partes[2], force=force)

        elif comando == "sair":
            print("Encerrando o programa. Até logo!")
            break

        else:
            print("Comando inválido. Tente novamente.")


if __name__ == "__main__":
    main()
