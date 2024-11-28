# Davi Santos Pacini - 22300504;
# Bruno Monteiro Fonseca - 22305939;
# Aleff Matheus - 22308138;
# Guilherme Miranda Cavalcante - 22301666;
# Davi Pereira Araújo - 22301354
# Bruno de Lima Marques - 22309108

import os
import hashlib
import getpass
import json
import random
import string
import shutil
USUARIO_FILE = "Usuarios.txt"
METADATA_FILE = "metadata.json"

def hash_password(password):
    salt = os.urandom(16).hex()  # Salt convertido para hexadecimal
    hashed_password = hashlib.sha512((salt + password).encode()).hexdigest()
    # Formato: algoritmo$salt$hash
    return f"$6${salt}${hashed_password}"


def SalvaUsuario(username, password):
    # Gera o salt como uma string de 16 caracteres aleatórios
    salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    # Calcula o hash da senha concatenada com o salt
    hashed_password = hashlib.sha512((salt + password).encode()).hexdigest()
    # Escreve no arquivo no formato: username:$6$salt$hash
    with open(USUARIO_FILE, "a") as file:
        file.write(f"{username}:$6${salt}${hashed_password}\n")

def CarregaUsuario():
    if not os.path.exists(USUARIO_FILE):
        return []
    
    usuarios = []
    with open(USUARIO_FILE, "r") as file:
        for line in file:
            line = line.strip()  # Remove espaços extras e quebras de linha
            if line:  # Ignora linhas vazias
                # Divide a linha no formato esperado: username:$6$salt$hash
                try:
                    username, hashed_data = line.split(":", 1)
                    # Verifica se o hash segue o formato correto: $6$salt$hash
                    parts = hashed_data.split("$")
                    if len(parts) == 4 and parts[1] == "6":
                        usuarios.append({"username": username, "hashed_data": hashed_data})
                    else:
                        print(f"Formato inválido para o usuário '{username}'. Ignorando... (hashed_data: {hashed_data})")
                except ValueError:
                    print(f"Erro ao processar linha: {line}")
    # print(f"Usuários carregados: {usuarios}")
    return usuarios

def VerificaLogin(username, password):
    usuarios = CarregaUsuario()
    if not usuarios:
        print("Nenhum usuário encontrado. Vamos criar um novo usuário.")
        return False
    for usuario in usuarios:
        if usuario["username"] == username:
            salt = usuario["hashed_data"].split("$")[2]
            hashed_password = hashlib.sha512((salt + password).encode()).hexdigest()
            if usuario["hashed_data"] == f"$6${salt}${hashed_password}":
                # print("Login bem-sucedido!")
                return True
            else:
                print("Senha incorreta.")
                return False
    print("Usuário não encontrado.")
    return False



# Função para criar um novo usuário
def criar_novo_usuario():
    username = input("Digite um nome de usuário: ")
    password = getpass.getpass("Digite uma senha: ")
    SalvaUsuario(username, password)
    print("Usuário criado com sucesso!")
    return username


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
        return username
    else:
        while True:
            print("Login")
            username = input("Digite seu nome de usuário: ")
            password = getpass.getpass("Digite sua senha: ")
            
            if VerificaLogin(username, password):
                print("Login realizado com sucesso!")
                return username
            else:
                print("Usuário ou senha incorretos. Tente novamente.")
                respo = input("Deseja criar um novo usuário? (s/n): ").strip().lower()
                if respo == "s":
                    criar_novo_usuario()
                else:
                    print("Vamos tentar novamente.")
                


def carrega_metadados():
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'r') as file:
            return json.load(file)
    return {}

def salva_metadados(metadados):
    with open(METADATA_FILE, 'w') as file:
        json.dump(metadados, file)


def salva_proprietario(caminho_arquivo, username):
    with open(f"{caminho_arquivo}.owner", 'w') as file:
        file.write(username)

def salva_proprietario(caminho, username):
    metadados = carrega_metadados()
    metadados[caminho] = username
    salva_metadados(metadados)

def verifica_proprietario(caminho, username):
    metadados = carrega_metadados()
    return metadados.get(caminho) == username

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

def Criar_arquivo(caminho_arquivo, username):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    conteudo = ''.join(random.choice(caracteres) for _ in range(100))
    try:
        with open(caminho_arquivo, 'w') as file:
            file.write(conteudo)  
        salva_proprietario(caminho_arquivo, username)
        print(f"Arquivo '{caminho_arquivo}' criado com sucesso.")
    except Exception as e:
        print(f"Erro ao criar arquivo '{caminho_arquivo}': {e}")

def apagar_arquivo(caminho_arquivo, username):
    try:
        if os.path.exists(caminho_arquivo):
            if verifica_proprietario(caminho_arquivo, username):
                os.remove(caminho_arquivo)
                metadados = carrega_metadados()
                metadados.pop(caminho_arquivo, None)
                salva_metadados(metadados)
                print(f"Arquivo '{caminho_arquivo}' apagado com sucesso.")
            else:
                print(f"Você não possui permissão para apagar o arquivo '{caminho_arquivo}'.")
        else:
            print(f"O arquivo '{caminho_arquivo}' não existe.")
    except Exception as e:
        print(f"Erro ao apagar arquivo '{caminho_arquivo}': {e}")

def criar_diretorio(caminho_diretorio, username):
    
    try:
        os.makedirs(caminho_diretorio, exist_ok=True)
        salva_proprietario(caminho_diretorio, username)
        print(f"diretorio'{caminho_diretorio}' criado com sucesso.")
    except Exception as e:
        print(f"erro ao criar diretorio'{caminho_diretorio}:{e}'")

def apagar_diretorio(caminho_diretorio, username):
    try:
        if os.path.exists(caminho_diretorio):
            if verifica_proprietario(caminho_diretorio, username):
                os.rmdir(caminho_diretorio)
                metadados = carrega_metadados()
                metadados.pop(caminho_diretorio, None)
                salva_metadados(metadados)
                print(f"Diretório '{caminho_diretorio}' excluído com sucesso.")
            else:
                print(f"Você não possui permissão para apagar o diretório '{caminho_diretorio}'.")
        else:
            print(f"O diretório '{caminho_diretorio}' não existe.")
    except OSError as e:
        print(f"Erro ao apagar diretório '{caminho_diretorio}': {e}")
    

def apagar_diretorio_nao_vazio(caminho_diretorio, username, force=False):
    if os.path.exists(caminho_diretorio):
        try:
            if verifica_proprietario(caminho_diretorio, username):
                if force:
                    shutil.rmtree(caminho_diretorio)
                    metadados = carrega_metadados()
                    # Remove metadados do diretório e seu conteúdo
                    for caminho in list(metadados.keys()):
                        if caminho.startswith(caminho_diretorio):
                            del metadados[caminho]
                    salva_metadados(metadados)
                    print(f"O diretório '{caminho_diretorio}' e todo o seu conteúdo foram apagados.")
                else:
                    os.rmdir(caminho_diretorio)
                    metadados = carrega_metadados()
                    metadados.pop(caminho_diretorio, None)
                    salva_metadados(metadados)
                    print(f"O diretório '{caminho_diretorio}' foi apagado.")
            else:
                print(f"Você não possui permissão para apagar o diretório '{caminho_diretorio}'.")
        except FileNotFoundError:
            print(f"O diretório '{caminho_diretorio}' não foi encontrado.")
        except PermissionError:
            print(f"Você não possui permissão para apagar o diretório '{caminho_diretorio}'.")
        except OSError as e:
            print(f"Erro ao apagar diretório '{caminho_diretorio}': {e}")
    else:
        print(f"O diretório '{caminho_diretorio}' não existe.")
        
def main():
    username = iniciar_shell()
    if not username:
        iniciar_shell()
        print("Nenhum usuário retornado.")
        return

    print(f"Usuário {username} logado com sucesso.")

    while True:
        comando = input("Digite um comando: ").strip().split()
        if not comando:
            continue

        acao = comando[0]
        if len(comando) > 2:
            tipo = comando[1]
            caminho = comando[2]
        else:
            tipo = ""
            caminho = comando[1] if len(comando) > 1 else ""

        if acao == "listar":
            listar_diretorio(caminho if caminho else None)
        elif acao == "criar" and tipo == "diretorio":
            criar_diretorio(caminho, username)
        elif acao == "criar" and tipo == "arquivo":
            Criar_arquivo(caminho, username)
        elif acao == "apagar" and tipo == "arquivo":
            apagar_arquivo(caminho, username)
        elif acao == "apagar" and tipo == "diretorio":
            if len(comando) > 3 and comando[3] == "--force":
                apagar_diretorio_nao_vazio(caminho, username, force=True)
            else:
                apagar_diretorio(caminho, username)
        elif acao == "sair":
            print("Encerrando o programa.")
            break
        else:
            print("Comando inválido. Tente novamente.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Erro fatal: {e}")
