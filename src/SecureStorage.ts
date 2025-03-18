/**
 * Classe permettant de chiffrer et déchiffrer les données stockées dans IndexedDB
 * en utilisant l'API Web Crypto.
 *
 * Cette classe utilise l'algorithme AES-GCM, qui fournit à la fois confidentialité et
 * authenticité des données, et génère des clés sécurisées avec PBKDF2.
 */
export class SecureStorage {
  private static readonly SALT_LENGTH = 16;
  private static readonly IV_LENGTH = 12;
  private static readonly KEY_LENGTH = 256; // bits
  private static readonly ITERATIONS = 100000;
  private static readonly ALGO = "AES-GCM";
  private static readonly KEY_DERIVATION = "PBKDF2";
  private masterKey: CryptoKey | null = null;
  private ready: Promise<void>;

  /**
   * Initialise le stockage sécurisé avec une clé maître dérivée du mot de passe fourni
   *
   * @param password - Le mot de passe utilisé pour dériver la clé de chiffrement
   * @param salt - Le sel utilisé pour la dérivation de clé (généré si non fourni)
   */
  constructor(password: string, salt?: Uint8Array) {
    this.ready = this.initialize(password, salt);
  }

  /**
   * Initialise la clé maître en la dérivant du mot de passe
   *
   * @param password - Mot de passe utilisateur
   * @param providedSalt - Sel optionnel (pour consistance entre les sessions)
   * @returns Promise qui se résout quand la clé est prête
   */
  private async initialize(
    password: string,
    providedSalt?: Uint8Array
  ): Promise<void> {
    try {
      // Générer ou utiliser le sel fourni
      const salt =
        providedSalt ||
        crypto.getRandomValues(new Uint8Array(SecureStorage.SALT_LENGTH));

      // Convertir le mot de passe en données binaires
      const passwordBuffer = new TextEncoder().encode(password);

      // Dériver une clé à partir du mot de passe avec PBKDF2
      const baseKey = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: SecureStorage.KEY_DERIVATION },
        false,
        ["deriveKey"]
      );

      // Générer la clé AES-GCM à partir de la clé de base
      this.masterKey = await crypto.subtle.deriveKey(
        {
          name: SecureStorage.KEY_DERIVATION,
          salt,
          iterations: SecureStorage.ITERATIONS,
          hash: "SHA-256",
        },
        baseKey,
        {
          name: SecureStorage.ALGO,
          length: SecureStorage.KEY_LENGTH,
        },
        false, // Non extractible pour la sécurité
        ["encrypt", "decrypt"]
      );

      // Stocker le sel de manière sécurisée pour une utilisation ultérieure
      // (nécessaire pour déchiffrer les données plus tard avec le même mot de passe)
      await this.saveSecurityParams(salt);
    } catch (error) {
      console.error("Erreur lors de l'initialisation du chiffrement:", error);
      throw new Error("Impossible d'initialiser le chiffrement");
    }
  }

  /**
   * Sauvegarde les paramètres de sécurité (comme le sel) dans IndexedDB
   *
   * @param salt - Le sel utilisé pour la dérivation de clé
   */
  private async saveSecurityParams(salt: Uint8Array): Promise<void> {
    // Ouvrir une base IndexedDB pour les paramètres de sécurité
    const db = await this.openSecurityDb();

    const transaction = db.transaction(["params"], "readwrite");
    const store = transaction.objectStore("params");

    // Stocker le sel pour une utilisation ultérieure
    await store.put({ id: "salt", value: salt });

    db.close();
  }

  /**
   * Récupère les paramètres de sécurité sauvegardés
   *
   * @returns Le sel précédemment sauvegardé
   */
  private async getSecurityParams(): Promise<Uint8Array | null> {
    try {
      const db = await this.openSecurityDb();
      const transaction = db.transaction(["params"], "readonly");
      const store = transaction.objectStore("params");

      const saltObj = await store.get("salt");
      db.close();

      return saltObj?.value || null;
    } catch (error) {
      console.error(
        "Erreur lors de la récupération des paramètres de sécurité:",
        error
      );
      return null;
    }
  }

  /**
   * Ouvre ou crée la base de données pour stocker les paramètres de sécurité
   */
  private openSecurityDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = window.indexedDB.open("SecureStorageParams", 1);

      request.onerror = (event) => {
        reject(
          new Error("Impossible d'accéder à la base de paramètres de sécurité")
        );
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
  public async encrypt<T>(
    data: T
  ): Promise<{ encryptedData: ArrayBuffer; iv: Uint8Array }> {
    // Attendre que l'initialisation soit terminée
    await this.ready;

    if (!this.masterKey) {
      throw new Error("Clé de chiffrement non initialisée");
    }

    try {
      // Convertir les données en format JSON puis en buffer
      const jsonString = JSON.stringify(data);
      const dataBuffer = new TextEncoder().encode(jsonString);

      // Générer un vecteur d'initialisation unique
      const iv = crypto.getRandomValues(
        new Uint8Array(SecureStorage.IV_LENGTH)
      );

      // Chiffrer les données
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: SecureStorage.ALGO,
          iv,
        },
        this.masterKey,
        dataBuffer
      );

      return { encryptedData, iv };
    } catch (error) {
      console.error("Erreur lors du chiffrement:", error);
      throw new Error("Échec du chiffrement des données");
    }
  }

  /**
   * Déchiffre des données précédemment chiffrées
   *
   * @param encryptedData - Les données chiffrées à déchiffrer
   * @param iv - Le vecteur d'initialisation utilisé lors du chiffrement
   * @returns Une promesse qui résout avec les données déchiffrées
   * @throws Erreur si le déchiffrement échoue
   */
  public async decrypt<T>(
    encryptedData: ArrayBuffer,
    iv: Uint8Array
  ): Promise<T> {
    // Attendre que l'initialisation soit terminée
    await this.ready;

    if (!this.masterKey) {
      throw new Error("Clé de chiffrement non initialisée");
    }

    try {
      // Déchiffrer les données
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: SecureStorage.ALGO,
          iv,
        },
        this.masterKey,
        encryptedData
      );

      // Convertir le buffer en chaîne JSON puis parser en objet
      const jsonString = new TextDecoder().decode(decryptedBuffer);
      return JSON.parse(jsonString) as T;
    } catch (error) {
      console.error("Erreur lors du déchiffrement:", error);
      throw new Error("Échec du déchiffrement des données");
    }
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
  public async storeEncrypted<T>(
    dbName: string,
    storeName: string,
    key: IDBValidKey,
    data: T
  ): Promise<void> {
    try {
      // Chiffrer les données
      const { encryptedData, iv } = await this.encrypt(data);

      // Ouvrir la base de données
      const db = await this.openDatabase(dbName, storeName);

      // Stocker les données chiffrées et l'IV ensemble
      const transaction = db.transaction([storeName], "readwrite");
      const store = transaction.objectStore(storeName);

      await store.put({
        key,
        encryptedData,
        iv,
        timestamp: new Date().getTime(),
      });

      db.close();
    } catch (error) {
      console.error("Erreur lors du stockage des données chiffrées:", error);
      throw new Error("Impossible de stocker les données chiffrées");
    }
  }

  /**
   * Récupère et déchiffre des données stockées dans IndexedDB
   *
   * @param dbName - Nom de la base de données
   * @param storeName - Nom du store d'objets
   * @param key - Clé des données à récupérer
   * @returns Promise qui résout avec les données déchiffrées, ou null si non trouvées
   */
  public async retrieveDecrypted<T>(
    dbName: string,
    storeName: string,
    key: IDBValidKey
  ): Promise<T | null> {
    try {
      // Ouvrir la base de données
      const db = await this.openDatabase(dbName, storeName);

      // Récupérer les données
      const transaction = db.transaction([storeName], "readonly");
      const store = transaction.objectStore(storeName);

      const result = await store.get(key);
      db.close();

      if (!result) {
        return null;
      }

      // Déchiffrer et retourner les données
      return await this.decrypt<T>(result.encryptedData, result.iv);
    } catch (error) {
      console.error("Erreur lors de la récupération des données:", error);
      throw new Error("Impossible de récupérer les données déchiffrées");
    }
  }

  /**
   * Ouvre ou crée une base de données IndexedDB
   *
   * @param dbName - Nom de la base de données
   * @param storeName - Nom du store d'objets à créer/utiliser
   * @returns Promise qui résout avec la connexion à la base de données
   */
  private openDatabase(
    dbName: string,
    storeName: string
  ): Promise<IDBDatabase> {
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
  public async changePassword(
    newPassword: string,
    dbName: string,
    storeNames: string[]
  ): Promise<void> {
    // Sauvegarder l'ancienne clé
    const oldKey = this.masterKey;

    if (!oldKey) {
      throw new Error("Clé de chiffrement actuelle non initialisée");
    }

    try {
      // Pour chaque store, récupérer toutes les données
      for (const storeName of storeNames) {
        const db = await this.openDatabase(dbName, storeName);
        const transaction = db.transaction([storeName], "readonly");
        const store = transaction.objectStore(storeName);

        // Récupérer toutes les entrées
        const allItems = await new Promise<any[]>((resolve, reject) => {
          const request = store.getAll();
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });

        db.close();

        // Initialiser la nouvelle clé
        await this.initialize(newPassword);

        // Recrypter et sauvegarder chaque entrée
        for (const item of allItems) {
          // Déchiffrer avec l'ancienne clé
          this.masterKey = oldKey;
          const decryptedData = await this.decrypt(item.encryptedData, item.iv);

          // Chiffrer avec la nouvelle clé et sauvegarder
          await this.storeEncrypted(dbName, storeName, item.key, decryptedData);
        }
      }
    } catch (error) {
      console.error("Erreur lors du changement de mot de passe:", error);
      throw new Error("Impossible de changer le mot de passe");
    }
  }
}
