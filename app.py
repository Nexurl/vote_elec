import json
import random
import hashlib
import secrets
from flask import Flask, render_template_string, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = "super_secret_key_pour_session_flask"

# ==============================================================================
# 1. OUTILS CRYPTOGRAPHIQUES (RSA & UTILITAIRES)
# ==============================================================================

def is_prime(n, k=5):
    """Test de primalité de Miller-Rabin pour générer des clés RSA."""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits=512):
    """Génère un nombre premier de n bits."""
    while True:
        num = secrets.randbits(bits)
        if num % 2 == 0: num += 1
        if is_prime(num):
            return num

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """Inverse modulaire: calcule x tel que (a * x) % m == 1"""
    return pow(a, -1, m)

def generate_keypair(bits=512):
    """Génère (public_key, private_key). Public=(e, n), Private=(d, n)."""
    # Note: Pour la démo, on utilise des tailles réduites pour la rapidité
    # Dans la vraie vie, utiliser 2048+ bits
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = modinv(e, phi)
    return ((e, n), (d, n))

def str_to_int(message):
    """Convertit un string en int pour le chiffrement RSA."""
    message_bytes = message.encode('utf-8')
    return int.from_bytes(message_bytes, byteorder='big')

def int_to_str(number):
    """Convertit un int RSA en string."""
    # Calcul de la taille en octets nécessaire
    try:
        length = (number.bit_length() + 7) // 8
        return number.to_bytes(length, byteorder='big').decode('utf-8')
    except:
        return None  # En cas d'échec de décodage (padding corrompu)

def hash_sha256(data):
    """Hashage SHA-256 standard."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

# ==============================================================================
# 2. ENTITÉS DU PROTOCOLE (Classes)
# ==============================================================================

class Commissaire:
    """
    Le Commissaire vérifie le droit de vote.
    Il possède la liste des N1 valides et les empreintes des N2 (N'2).
    """
    def __init__(self):
        self.valid_n1 = set()
        self.hashed_n2 = set()

    def charger_listes(self, liste_n1, liste_hashed_n2):
        self.valid_n1 = set(liste_n1)
        self.hashed_n2 = set(liste_hashed_n2)

    def verifier_n1(self, n1):
        return n1 in self.valid_n1

    def consommer_n1(self, n1):
        """Utilisé par l'anonymiseur lors du dépôt."""
        if n1 in self.valid_n1:
            self.valid_n1.remove(n1)
            return True
        return False

    def verifier_n2_hash(self, n2_clear):
        """Utilisé par le décompteur lors du dépouillement."""
        h = hash_sha256(n2_clear)
        return h in self.hashed_n2

class Administrateur:
    """
    L'Administrateur signe les bulletins à l'aveugle.
    Possède une paire de clés RSA.
    """
    def __init__(self):
        self.public_key, self.private_key = generate_keypair(bits=1024)

    def verifier_eligibilite(self, commissaire, n1):
        return commissaire.verifier_n1(n1)

    def signer_aveugle(self, blinded_message_int):
        """
        Signature à l'aveugle : s' = (m')^d mod N
        L'admin ne voit que m' (le message masqué).
        """
        d, n = self.private_key
        signature_blinded = pow(blinded_message_int, d, n)
        return signature_blinded

class Anonymiseur:
    """
    L'Anonymiseur sert d'urne.
    Il stocke les bulletins chiffrés.
    """
    def __init__(self):
        self.urne = []  # Liste de bulletins chiffrés

    def recevoir_vote(self, commissaire, n1, vote_chiffre):
        """
        1. Vérifie N1 auprès du commissaire.
        2. Si valide, demande au commissaire de rayer N1.
        3. Stocke le vote chiffré.
        """
        if commissaire.consommer_n1(n1):
            self.urne.append(vote_chiffre)
            return True
        return False

class Decompteur:
    """
    Le Décompteur dépouille.
    Possède sa propre paire de clés RSA pour le chiffrement de l'enveloppe.
    """
    def __init__(self):
        self.public_key, self.private_key = generate_keypair(bits=1024)
        self.resultats = {}

    def depouiller(self, anonymiseur, admin_pub_key, commissaire):
        """
        Processus de dépouillement complet.
        """
        bulletins_valides = []
        d, n_self = self.private_key
        e_admin, n_admin = admin_pub_key
        
        logs = []

        for enveloppe in anonymiseur.urne:
            # 1. Déchiffrement de l'enveloppe (RSA Décompteur)
            # enveloppe est un tuple (msg_chiffre, signature_chiffree) ou structure similaire
            # Pour simplifier, on assume que l'enveloppe contient [int_message, int_signature] chiffrés
            
            # Note : Dans le protocole décrit, l'enveloppe contient le "Vote Signé".
            # Le "Vote Signé" est le couple (MessageClair, Signature).
            # Tout cela est chiffré avec la clé publique du Décompteur.
            
            try:
                # Déchiffrement (Textbook RSA pour la démo)
                m_int_chiffre, s_int_chiffre = enveloppe
                
                m_int = pow(m_int_chiffre, d, n_self)
                s_int = pow(s_int_chiffre, d, n_self)
                
                message_clair = int_to_str(m_int)
                if not message_clair:
                    logs.append("Erreur: Impossible de décoder le bulletin.")
                    continue

                # Structure du bulletin : "CHOIX||N2||ALEA"
                parts = message_clair.split("||")
                if len(parts) != 3:
                    logs.append("Erreur: Format bulletin invalide.")
                    continue
                
                choix_vote = parts[0]
                n2_code = parts[1]
                
                # 2. Vérification de la signature de l'administrateur
                # On vérifie si s^e mod N_admin == m
                verification = pow(s_int, e_admin, n_admin)
                
                if verification != m_int:
                    logs.append(f"Fraude: Signature admin invalide pour {n2_code}...")
                    continue
                
                # 3. Vérification N2 auprès du commissaire
                if not commissaire.verifier_n2_hash(n2_code):
                    logs.append(f"Fraude: Code N2 invalide ou déjà utilisé ({n2_code}).")
                    continue
                
                # Vote validé
                bulletins_valides.append(choix_vote)
                logs.append(f"Succès: Vote validé pour {choix_vote}.")

            except Exception as e:
                logs.append(f"Exception durant le dépouillement: {str(e)}")

        # Comptage
        from collections import Counter
        self.resultats = dict(Counter(bulletins_valides))
        return self.resultats, logs

# ==============================================================================
# 3. INITIALISATION ET VARIABLES GLOBALES
# ==============================================================================

# Instanciation des entités
commissaire = Commissaire()
admin = Administrateur()
anonymiseur = Anonymiseur()
decompteur = Decompteur()

# Base de données fictive (JSON en mémoire)
# Nom du fichier de stockage
DATA_FILE = "electeurs.json"

def load_voters():
    """Charge la liste des électeurs depuis le fichier JSON."""
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_voters(voters_list):
    """Sauvegarde la liste des électeurs dans le fichier JSON."""
    with open(DATA_FILE, 'w') as f:
        json.dump(voters_list, f, indent=4)

def init_scrutin():
    """Génère des électeurs, sauvegarde dans JSON et initialise le commissaire."""
    voters = [] # On crée une liste locale
    
    n1_list = []
    n2_hashed_list = []
    
    # Création de 5 électeurs fictifs
    for i in range(1, 6):
        n1 = secrets.token_hex(6).upper()
        n2 = secrets.token_hex(6).upper()
        
        voter = {
            "id": i,
            "name": f"Citoyen {i}",
            "n1": n1,
            "n2": n2,
            "has_voted": False
        }
        voters.append(voter)
        
        n1_list.append(n1)
        n2_hashed_list.append(hash_sha256(n2))
    
    # Sauvegarde dans le fichier JSON
    save_voters(voters)
    
    # Le commissaire reçoit les listes (en mémoire pour la session)
    commissaire.charger_listes(n1_list, n2_hashed_list)
    
    # Vider l'urne
    anonymiseur.urne = []

# Lancer l'initialisation au démarrage
init_scrutin()

# ==============================================================================
# 4. INTERFACE WEB ET ROUTAGE
# ==============================================================================

with open("templates/index.html", "r", encoding="utf-8") as f:
    HTML_TEMPLATE = f.read()

with open("templates/vote.html", "r", encoding="utf-8") as f:
    VOTE_PAGE_TEMPLATE = f.read()

@app.route('/')
def index():
    # On charge depuis le fichier
    voters = load_voters()
    return render_template_string(HTML_TEMPLATE, 
                                  voters=voters,  # <-- Modification ici
                                  urne_count=len(anonymiseur.urne),
                                  admin_key=admin.public_key,
                                  teller_key=decompteur.public_key,
                                  resultats=session.get('resultats'),
                                  logs=session.get('logs'))

@app.route('/reset')
def reset():
    init_scrutin()
    session.pop('resultats', None)
    session.pop('logs', None)
    return redirect(url_for('index'))

@app.route('/vote_ui/<int:voter_id>')
def vote_ui(voter_id):
    voters = load_voters() # <-- Chargement
    voter = next((v for v in voters if v["id"] == voter_id), None)
    if not voter: return "Electeur introuvable"
    return render_template_string(VOTE_PAGE_TEMPLATE, voter=voter)

@app.route('/submit_vote/<int:voter_id>', methods=['POST'])
def submit_vote(voter_id):
    """
    Cette route simule le LOGICIEL DE VOTE sur l'ordinateur du client.
    Elle orchestre les échanges crypto complexes.
    """
    voters = load_voters()
    voter = next((v for v in voters if v["id"] == voter_id), None)
    choix = request.form['choix']
    n1 = voter['n1']
    n2 = voter['n2'] # Connu seulement du client ici

    # --- ÉTAPE 1: Vérification Droit de Vote (Admin <-> Commissaire) ---
    # Le client envoie N1 à l'admin
    if not admin.verifier_eligibilite(commissaire, n1):
        return "Erreur: Code N1 invalide ou refusé par l'administrateur."

    # --- ÉTAPE 2: Préparation du bulletin (Client) ---
    # Format: VOTE||N2||ALEA
    salt = secrets.token_hex(8)
    message_clair = f"{choix}||{n2}||{salt}"
    m_int = str_to_int(message_clair)
    
    # --- ÉTAPE 3: Signature à l'Aveugle (Client <-> Admin) ---
    # a) Masquage (Client)
    e_admin, n_admin = admin.public_key
    
    # Choisir un facteur k aléatoire premier avec n_admin
    while True:
        k = random.randrange(2, n_admin - 1)
        if gcd(k, n_admin) == 1:
            break
            
    # m' = m * k^e mod N
    blind_factor = pow(k, e_admin, n_admin)
    m_prime = (m_int * blind_factor) % n_admin
    
    # b) Signature par l'Admin (ne voit que m_prime)
    s_prime = admin.signer_aveugle(m_prime)
    
    # c) Démasquage (Client)
    # s = s' * k^-1 mod N
    k_inv = modinv(k, n_admin)
    signature = (s_prime * k_inv) % n_admin
    
    # Vérification locale (optionnelle mais recommandée)
    # s^e == m ?
    if pow(signature, e_admin, n_admin) != m_int:
        return "Erreur critique: La signature de l'admin ne correspond pas !"

    # --- ÉTAPE 4: Mise sous enveloppe pour le Décompteur (Client) ---
    # On chiffre le Message ET la Signature avec la clé publique du Décompteur.
    e_teller, n_teller = decompteur.public_key
    
    # Chiffrement RSA simple (m^e mod N) pour la démo
    # En pratique : utiliser PKCS1_OAEP
    encrypted_message = pow(m_int, e_teller, n_teller)
    encrypted_signature = pow(signature, e_teller, n_teller)
    
    enveloppe = (encrypted_message, encrypted_signature)

    # --- ÉTAPE 5: Envoi à l'Anonymiseur (Client -> Anonymiseur) ---
    succes = anonymiseur.recevoir_vote(commissaire, n1, enveloppe)
    
    if succes:
        voter['has_voted'] = True
        save_voters(voters) # <-- On sauvegarde le changement d'état dans le JSON

        return redirect(url_for('index'))
    else:
        return "Erreur lors du dépôt du vote (N1 probablement déjà utilisé)."

@app.route('/depouiller', methods=['POST'])
def route_depouiller():
    resultats, logs = decompteur.depouiller(anonymiseur, admin.public_key, commissaire)
    session['resultats'] = resultats
    session['logs'] = logs
    return redirect(url_for('index'))

if __name__ == '__main__':
    print("Application lancée sur http://127.0.0.1:5000")
    app.run(debug=True)