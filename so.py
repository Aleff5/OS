import os
import hashlib
import getpass
import json
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