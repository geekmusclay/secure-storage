/******************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise, SuppressedError, Symbol, Iterator */


function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
    var e = new Error(message);
    return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
};

/**
 * Classe permettant de chiffrer et déchiffrer les données stockées dans IndexedDB
 * en utilisant l'API Web Crypto.
 *
 * Cette classe utilise l'algorithme AES-GCM, qui fournit à la fois confidentialité et
 * authenticité des données, et génère des clés sécurisées avec PBKDF2.
 */
class SecureStorage {
    /**
     * Initialise le stockage sécurisé avec une clé maître dérivée du mot de passe fourni
     *
     * @param password - Le mot de passe utilisé pour dériver la clé de chiffrement
     * @param salt - Le sel utilisé pour la dérivation de clé (généré si non fourni)
     */
    constructor(password, salt) {
        this.masterKey = null;
        this.ready = this.initialize(password, salt);
    }
    /**
     * Initialise la clé maître en la dérivant du mot de passe
     *
     * @param password - Mot de passe utilisateur
     * @param providedSalt - Sel optionnel (pour consistance entre les sessions)
     * @returns Promise qui se résout quand la clé est prête
     */
    initialize(password, providedSalt) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Générer ou utiliser le sel fourni
                const salt = providedSalt ||
                    crypto.getRandomValues(new Uint8Array(SecureStorage.SALT_LENGTH));
                // Convertir le mot de passe en données binaires
                const passwordBuffer = new TextEncoder().encode(password);
                // Dériver une clé à partir du mot de passe avec PBKDF2
                const baseKey = yield crypto.subtle.importKey("raw", passwordBuffer, { name: SecureStorage.KEY_DERIVATION }, false, ["deriveKey"]);
                // Générer la clé AES-GCM à partir de la clé de base
                this.masterKey = yield crypto.subtle.deriveKey({
                    name: SecureStorage.KEY_DERIVATION,
                    salt,
                    iterations: SecureStorage.ITERATIONS,
                    hash: "SHA-256",
                }, baseKey, {
                    name: SecureStorage.ALGO,
                    length: SecureStorage.KEY_LENGTH,
                }, false, // Non extractible pour la sécurité
                ["encrypt", "decrypt"]);
                // Stocker le sel de manière sécurisée pour une utilisation ultérieure
                // (nécessaire pour déchiffrer les données plus tard avec le même mot de passe)
                yield this.saveSecurityParams(salt);
            }
            catch (error) {
                console.error("Erreur lors de l'initialisation du chiffrement:", error);
                throw new Error("Impossible d'initialiser le chiffrement");
            }
        });
    }
    /**
     * Sauvegarde les paramètres de sécurité (comme le sel) dans IndexedDB
     *
     * @param salt - Le sel utilisé pour la dérivation de clé
     */
    saveSecurityParams(salt) {
        return __awaiter(this, void 0, void 0, function* () {
            // Ouvrir une base IndexedDB pour les paramètres de sécurité
            const db = yield this.openSecurityDb();
            const transaction = db.transaction(["params"], "readwrite");
            const store = transaction.objectStore("params");
            // Stocker le sel pour une utilisation ultérieure
            yield store.put({ id: "salt", value: salt });
            db.close();
        });
    }
    /**
     * Récupère les paramètres de sécurité sauvegardés
     *
     * @returns Le sel précédemment sauvegardé
     */
    getSecurityParams() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const db = yield this.openSecurityDb();
                const transaction = db.transaction(["params"], "readonly");
                const store = transaction.objectStore("params");
                const saltObj = yield store.get("salt");
                db.close();
                return (saltObj === null || saltObj === void 0 ? void 0 : saltObj.value) || null;
            }
            catch (error) {
                console.error("Erreur lors de la récupération des paramètres de sécurité:", error);
                return null;
            }
        });
    }
    /**
     * Ouvre ou crée la base de données pour stocker les paramètres de sécurité
     */
    openSecurityDb() {
        return new Promise((resolve, reject) => {
            const request = window.indexedDB.open("SecureStorageParams", 1);
            request.onerror = (event) => {
                reject(new Error("Impossible d'accéder à la base de paramètres de sécurité"));
            };
            request.onsuccess = (event) => {
                resolve(request.result);
            };
            request.onupgradeneeded = (event) => {
                const db = request.result;
                // Créer un store pour les paramètres de sécurité
                if (!db.objectStoreNames.contains("params")) {
                    db.createObjectStore("params", { keyPath: "id" });
                }
            };
        });
    }
    /**
     * Chiffre des données pour un stockage sécurisé
     *
     * @param data - Les données à chiffrer (peut être de n'importe quel type JSON-sérialisable)
     * @returns Une promesse qui résout avec un objet contenant les données chiffrées et le vecteur d'initialisation
     * @throws Erreur si le chiffrement échoue
     */
    encrypt(data) {
        return __awaiter(this, void 0, void 0, function* () {
            // Attendre que l'initialisation soit terminée
            yield this.ready;
            if (!this.masterKey) {
                throw new Error("Clé de chiffrement non initialisée");
            }
            try {
                // Convertir les données en format JSON puis en buffer
                const jsonString = JSON.stringify(data);
                const dataBuffer = new TextEncoder().encode(jsonString);
                // Générer un vecteur d'initialisation unique
                const iv = crypto.getRandomValues(new Uint8Array(SecureStorage.IV_LENGTH));
                // Chiffrer les données
                const encryptedData = yield crypto.subtle.encrypt({
                    name: SecureStorage.ALGO,
                    iv,
                }, this.masterKey, dataBuffer);
                return { encryptedData, iv };
            }
            catch (error) {
                console.error("Erreur lors du chiffrement:", error);
                throw new Error("Échec du chiffrement des données");
            }
        });
    }
    /**
     * Déchiffre des données précédemment chiffrées
     *
     * @param encryptedData - Les données chiffrées à déchiffrer
     * @param iv - Le vecteur d'initialisation utilisé lors du chiffrement
     * @returns Une promesse qui résout avec les données déchiffrées
     * @throws Erreur si le déchiffrement échoue
     */
    decrypt(encryptedData, iv) {
        return __awaiter(this, void 0, void 0, function* () {
            // Attendre que l'initialisation soit terminée
            yield this.ready;
            if (!this.masterKey) {
                throw new Error("Clé de chiffrement non initialisée");
            }
            try {
                // Déchiffrer les données
                const decryptedBuffer = yield crypto.subtle.decrypt({
                    name: SecureStorage.ALGO,
                    iv,
                }, this.masterKey, encryptedData);
                // Convertir le buffer en chaîne JSON puis parser en objet
                const jsonString = new TextDecoder().decode(decryptedBuffer);
                return JSON.parse(jsonString);
            }
            catch (error) {
                console.error("Erreur lors du déchiffrement:", error);
                throw new Error("Échec du déchiffrement des données");
            }
        });
    }
    /**
     * Utilitaire pour enregistrer des données chiffrées dans IndexedDB
     *
     * @param dbName - Nom de la base de données
     * @param storeName - Nom du store d'objets
     * @param key - Clé sous laquelle stocker les données
     * @param data - Données à chiffrer et stocker
     * @returns Promise qui se résout quand les données sont stockées
     */
    storeEncrypted(dbName, storeName, key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Chiffrer les données
                const { encryptedData, iv } = yield this.encrypt(data);
                // Ouvrir la base de données
                const db = yield this.openDatabase(dbName, storeName);
                // Stocker les données chiffrées et l'IV ensemble
                const transaction = db.transaction([storeName], "readwrite");
                const store = transaction.objectStore(storeName);
                yield store.put({
                    key,
                    encryptedData,
                    iv,
                    timestamp: new Date().getTime(),
                });
                db.close();
            }
            catch (error) {
                console.error("Erreur lors du stockage des données chiffrées:", error);
                throw new Error("Impossible de stocker les données chiffrées");
            }
        });
    }
    /**
     * Récupère et déchiffre des données stockées dans IndexedDB
     *
     * @param dbName - Nom de la base de données
     * @param storeName - Nom du store d'objets
     * @param key - Clé des données à récupérer
     * @returns Promise qui résout avec les données déchiffrées, ou null si non trouvées
     */
    retrieveDecrypted(dbName, storeName, key) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                // Ouvrir la base de données
                const db = yield this.openDatabase(dbName, storeName);
                // Récupérer les données
                const transaction = db.transaction([storeName], "readonly");
                const store = transaction.objectStore(storeName);
                const result = yield store.get(key);
                db.close();
                if (!result) {
                    return null;
                }
                // Déchiffrer et retourner les données
                return yield this.decrypt(result.encryptedData, result.iv);
            }
            catch (error) {
                console.error("Erreur lors de la récupération des données:", error);
                throw new Error("Impossible de récupérer les données déchiffrées");
            }
        });
    }
    /**
     * Ouvre ou crée une base de données IndexedDB
     *
     * @param dbName - Nom de la base de données
     * @param storeName - Nom du store d'objets à créer/utiliser
     * @returns Promise qui résout avec la connexion à la base de données
     */
    openDatabase(dbName, storeName) {
        return new Promise((resolve, reject) => {
            const request = window.indexedDB.open(dbName, 1);
            request.onerror = () => {
                reject(new Error(`Impossible d'ouvrir la base de données ${dbName}`));
            };
            request.onsuccess = () => {
                resolve(request.result);
            };
            request.onupgradeneeded = (event) => {
                const db = request.result;
                if (!db.objectStoreNames.contains(storeName)) {
                    db.createObjectStore(storeName, { keyPath: "key" });
                }
            };
        });
    }
    /**
     * Change le mot de passe utilisé pour le chiffrement
     * Recrypte toutes les données dans la base spécifiée avec la nouvelle clé
     *
     * @param newPassword - Nouveau mot de passe
     * @param dbName - Nom de la base de données contenant les données à recrypter
     * @param storeNames - Noms des stores à recrypter
     * @returns Promise qui se résout quand toutes les données sont recryptées
     */
    changePassword(newPassword, dbName, storeNames) {
        return __awaiter(this, void 0, void 0, function* () {
            // Sauvegarder l'ancienne clé
            const oldKey = this.masterKey;
            if (!oldKey) {
                throw new Error("Clé de chiffrement actuelle non initialisée");
            }
            try {
                // Pour chaque store, récupérer toutes les données
                for (const storeName of storeNames) {
                    const db = yield this.openDatabase(dbName, storeName);
                    const transaction = db.transaction([storeName], "readonly");
                    const store = transaction.objectStore(storeName);
                    // Récupérer toutes les entrées
                    const allItems = yield new Promise((resolve, reject) => {
                        const request = store.getAll();
                        request.onsuccess = () => resolve(request.result);
                        request.onerror = () => reject(request.error);
                    });
                    db.close();
                    // Initialiser la nouvelle clé
                    yield this.initialize(newPassword);
                    // Recrypter et sauvegarder chaque entrée
                    for (const item of allItems) {
                        // Déchiffrer avec l'ancienne clé
                        this.masterKey = oldKey;
                        const decryptedData = yield this.decrypt(item.encryptedData, item.iv);
                        // Chiffrer avec la nouvelle clé et sauvegarder
                        yield this.storeEncrypted(dbName, storeName, item.key, decryptedData);
                    }
                }
            }
            catch (error) {
                console.error("Erreur lors du changement de mot de passe:", error);
                throw new Error("Impossible de changer le mot de passe");
            }
        });
    }
}
SecureStorage.SALT_LENGTH = 16;
SecureStorage.IV_LENGTH = 12;
SecureStorage.KEY_LENGTH = 256; // bits
SecureStorage.ITERATIONS = 100000;
SecureStorage.ALGO = "AES-GCM";
SecureStorage.KEY_DERIVATION = "PBKDF2";

export { SecureStorage };
//# sourceMappingURL=secure-storage.esm.js.map
