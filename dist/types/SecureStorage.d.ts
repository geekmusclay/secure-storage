/**
 * Classe permettant de chiffrer et déchiffrer les données stockées dans IndexedDB
 * en utilisant l'API Web Crypto.
 *
 * Cette classe utilise l'algorithme AES-GCM, qui fournit à la fois confidentialité et
 * authenticité des données, et génère des clés sécurisées avec PBKDF2.
 */
export declare class SecureStorage {
    private static readonly SALT_LENGTH;
    private static readonly IV_LENGTH;
    private static readonly KEY_LENGTH;
    private static readonly ITERATIONS;
    private static readonly ALGO;
    private static readonly KEY_DERIVATION;
    private masterKey;
    private ready;
    /**
     * Initialise le stockage sécurisé avec une clé maître dérivée du mot de passe fourni
     *
     * @param password - Le mot de passe utilisé pour dériver la clé de chiffrement
     * @param salt - Le sel utilisé pour la dérivation de clé (généré si non fourni)
     */
    constructor(password: string, salt?: Uint8Array);
    /**
     * Initialise la clé maître en la dérivant du mot de passe
     *
     * @param password - Mot de passe utilisateur
     * @param providedSalt - Sel optionnel (pour consistance entre les sessions)
     * @returns Promise qui se résout quand la clé est prête
     */
    private initialize;
    /**
     * Sauvegarde les paramètres de sécurité (comme le sel) dans IndexedDB
     *
     * @param salt - Le sel utilisé pour la dérivation de clé
     */
    private saveSecurityParams;
    /**
     * Récupère les paramètres de sécurité sauvegardés
     *
     * @returns Le sel précédemment sauvegardé
     */
    private getSecurityParams;
    /**
     * Ouvre ou crée la base de données pour stocker les paramètres de sécurité
     */
    private openSecurityDb;
    /**
     * Chiffre des données pour un stockage sécurisé
     *
     * @param data - Les données à chiffrer (peut être de n'importe quel type JSON-sérialisable)
     * @returns Une promesse qui résout avec un objet contenant les données chiffrées et le vecteur d'initialisation
     * @throws Erreur si le chiffrement échoue
     */
    encrypt<T>(data: T): Promise<{
        encryptedData: ArrayBuffer;
        iv: Uint8Array;
    }>;
    /**
     * Déchiffre des données précédemment chiffrées
     *
     * @param encryptedData - Les données chiffrées à déchiffrer
     * @param iv - Le vecteur d'initialisation utilisé lors du chiffrement
     * @returns Une promesse qui résout avec les données déchiffrées
     * @throws Erreur si le déchiffrement échoue
     */
    decrypt<T>(encryptedData: ArrayBuffer, iv: Uint8Array): Promise<T>;
    /**
     * Utilitaire pour enregistrer des données chiffrées dans IndexedDB
     *
     * @param dbName - Nom de la base de données
     * @param storeName - Nom du store d'objets
     * @param key - Clé sous laquelle stocker les données
     * @param data - Données à chiffrer et stocker
     * @returns Promise qui se résout quand les données sont stockées
     */
    storeEncrypted<T>(dbName: string, storeName: string, key: IDBValidKey, data: T): Promise<void>;
    /**
     * Récupère et déchiffre des données stockées dans IndexedDB
     *
     * @param dbName - Nom de la base de données
     * @param storeName - Nom du store d'objets
     * @param key - Clé des données à récupérer
     * @returns Promise qui résout avec les données déchiffrées, ou null si non trouvées
     */
    retrieveDecrypted<T>(dbName: string, storeName: string, key: IDBValidKey): Promise<T | null>;
    /**
     * Ouvre ou crée une base de données IndexedDB
     *
     * @param dbName - Nom de la base de données
     * @param storeName - Nom du store d'objets à créer/utiliser
     * @returns Promise qui résout avec la connexion à la base de données
     */
    private openDatabase;
    /**
     * Change le mot de passe utilisé pour le chiffrement
     * Recrypte toutes les données dans la base spécifiée avec la nouvelle clé
     *
     * @param newPassword - Nouveau mot de passe
     * @param dbName - Nom de la base de données contenant les données à recrypter
     * @param storeNames - Noms des stores à recrypter
     * @returns Promise qui se résout quand toutes les données sont recryptées
     */
    changePassword(newPassword: string, dbName: string, storeNames: string[]): Promise<void>;
}
