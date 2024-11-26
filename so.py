import os
import hashlib
import getpass
import json
import random
import string
import shutil
USUARIO_FILE = "Usuarios.txt"

def hash_password(password):
    salt = os.urandom(16)
    hash_pass = hashlib.sha512(salt + password.encode()).hexdigest()
    return hash_pass, salt

def SalvaUsuario (username, password):
    hash_password, salt = hash_password(password)

    userData = {
        "username": username,
        "salt": salt.hex(),
        "password": hash_password
    }
    with open(USUARIO_FILE, "a") as file:
        file.write(json.dumps(userData) + "\n")

def CarregaUsuario():
    if not os.path.exists(USUARIO_FILE):
        return[]
    usuarios = []

    with open(USUARIO_FILE, 'r') as file:
        for line in file:
            usuarios.append(json.loads(line.strip()))
    return usuarios

def VerificaLogin(username, password):
    usuarios = CarregaUsuario()
    for user in usuarios:
        if user["username"] == username:
            # Obtém o salt e o hash do usuário
            salt = bytes.fromhex(user["salt"])
            hashed_password = hashlib.sha512(salt + password.encode()).hexdigest()
            
            # Verifica se o hash calculado é igual ao hash salvo
            if hashed_password == user["hashed_password"]:
                return True
            else:
                return False
    return False


def iniciar_shell():
    """
    Função inicial que verifica se há usuários cadastrados e solicita cadastro ou login.
    """
    usuarios = CarregaUsuario()

    if not usuarios:
        print("Nenhum usuário encontrado. Vamos criar um novo usuário.")
        username = input("Digite um nome de usuário: ")
        password = getpass.getpass("Digite uma senha: ")  # Oculta a senha enquanto o usuário digita
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



def listar_diretorio(diretorio=None):
    if diretorio is None:
        diretorio = os.getcwd()  
    
    try:
        conteudo = os.listdir(diretorio)  
        
        if not conteudo:
            print(f"O diretório '{diretorio}' está vazio.")
        else:
            print(f"Conteúdo de '{diretorio}':")
            for item in conteudo:
                print(item)
    except FileNotFoundError:
        print(f"O diretório '{diretorio}' não foi encontrado.")
    except PermissionError:
        print(f"Permissão negada para acessar o diretório '{diretorio}'.")

def Criar_arquivo(caminho_arquivo):

    conteudo = ''.join(random.choices(string.ascii_letters+ string.digits,k=100))

    try:
        diretorio = os.path.dirname(caminho_arquivo)
        if diretorio and not os.path.exists(diretorio):
            os.makedirs(diretorio)


        with open(caminho_arquivo, 'w')as file:
            file.write(conteudo)
        print(f"arquivo '{caminho_arquivo}'criado com sucesso.")
    except Exception as e :
        print(f"erro ao criar arquivo:{e}")

def apagar_arquivo(caminho_arquivo):
    
    try:
        if os.path.exists(caminho_arquivo):
            os.remove(caminho_arquivo)
            print(f"arquivo '{caminho_arquivo}'apagado com sucesso.")
        else:
            print(f"arquivo'{caminho_arquivo}'não existe.")
    except Exception as e:
        print(f"erro ao apagar arquivo '{caminho_arquivo}':{e}")

def criar_diretorio(caminho_diretorio):
    
    try:
        os.makedirs(caminho_diretorio, exist_ok=True)
        print(f"diretorio'{caminho_diretorio}' criado com sucesso.")
    except Exception as e:
        print(f"erro ao criar diretorio'{caminho_diretorio}:{e}'")

def apagar_diretorio(caminho_diretorio):
    
    try:
        if os.path.exists(caminho_diretorio):
            os.rmdir(caminho_diretorio)
            print(f"diretorio '{caminho_diretorio}'excluido com sucesso.")
        else:
            print(f"o diretorio '{caminho_diretorio} não existe'")

    except Exception as e:
        print(f"erro ao apagar diretorio'{caminho_diretorio}':{e}")

def apagar_diretorio_nao_vazio(caminho_diretorio, force=False):
    if os.path.exists(caminho_diretorio):
        try:
            if force:
                shutil.rmtree(caminho_diretorio)
                print(f"O diretório '{caminho_diretorio}' e todo o seu conteúdo foram apagados.")
            else:
                os.rmdir(caminho_diretorio)
                print(f"O diretório '{caminho_diretorio}' foi apagado.")
        except FileNotFoundError:
            print(f"O diretório '{caminho_diretorio}' não foi encontrado.")
        except PermissionError:
            print(f"Você não possui permissão para apagar o diretório '{caminho_diretorio}'.")
        except OSError as e:
            print(f"Erro ao apagar o diretório '{caminho_diretorio}': {e}")
    else:
        print(f"O diretório '{caminho_diretorio}' não existe.")