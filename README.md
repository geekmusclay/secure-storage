# Secure Storage

Une implémentation sécurisée pour le stockage de données dans IndexedDB utilisant l'API Web Crypto.

## Fonctionnalités

- Chiffrement AES-GCM pour la confidentialité et l'authenticité des données
- Dérivation de clé sécurisée avec PBKDF2
- Support TypeScript, Node.js et JavaScript vanilla
- Stockage persistant avec IndexedDB
- Changement de mot de passe avec re-chiffrement automatique des données

## Installation

```bash
npm install https://github.com/geekmusclay/secure-storage
```

## Utilisation

### TypeScript / ES Modules
```typescript
import { SecureStorage } from 'secure-storage';

// Interface pour typer vos données
interface UserData {
  id: number;
  name: string;
  preferences: {
    theme: 'light' | 'dark';
  };
}

// Initialisation
const storage = new SecureStorage('votre-mot-de-passe');

// Stockage de données
await storage.storeEncrypted(
  'ma-base',          // nom de la base IndexedDB
  'utilisateurs',     // nom du store
  'user_1',          // clé
  {                   // données à chiffrer
    id: 1,
    name: 'Jean',
    preferences: { theme: 'dark' }
  }
);

// Récupération de données
const data = await storage.retrieveDecrypted<UserData>(
  'ma-base',
  'utilisateurs',
  'user_1'
);

// Changement de mot de passe (recrypte toutes les données)
await storage.changePassword(
  'nouveau-mot-de-passe',
  'ma-base',
  ['utilisateurs']
);
```

### Node.js (CommonJS)
```javascript
const { SecureStorage } = require('secure-storage');

const storage = new SecureStorage('votre-mot-de-passe');
// ... même utilisation que ci-dessus
```

### Navigateur (UMD)
```html
<script src="node_modules/secure-storage/dist/secure-storage.umd.js"></script>
<script>
  const storage = new SecureStorage('votre-mot-de-passe');
  
  async function storeUserData() {
    try {
      await storage.storeEncrypted('ma-base', 'utilisateurs', 'user_1', {
        id: 1,
        name: 'Jean',
        preferences: { theme: 'dark' }
      });
      
      const data = await storage.retrieveDecrypted('ma-base', 'utilisateurs', 'user_1');
      console.log('Données récupérées:', data);
    } catch (error) {
      console.error('Erreur:', error);
    }
  }
</script>
```

## API

### `constructor(password: string, salt?: Uint8Array)`
Initialise le stockage sécurisé avec une clé maître dérivée du mot de passe.
- `password`: Mot de passe utilisé pour dériver la clé de chiffrement
- `salt`: Optionnel, sel pour la dérivation de clé (généré si non fourni)

### `storeEncrypted<T>(dbName: string, storeName: string, key: IDBValidKey, data: T): Promise<void>`
Chiffre et stocke des données dans IndexedDB.
- `dbName`: Nom de la base de données
- `storeName`: Nom du store d'objets
- `key`: Clé sous laquelle stocker les données
- `data`: Données à chiffrer (doit être JSON-sérialisable)

### `retrieveDecrypted<T>(dbName: string, storeName: string, key: IDBValidKey): Promise<T | null>`
Récupère et déchiffre des données stockées.
- `dbName`: Nom de la base de données
- `storeName`: Nom du store d'objets
- `key`: Clé des données à récupérer
- Retourne `null` si les données n'existent pas

### `changePassword(newPassword: string, dbName: string, storeNames: string[]): Promise<void>`
Change le mot de passe et recrypte toutes les données.
- `newPassword`: Nouveau mot de passe
- `dbName`: Nom de la base de données
- `storeNames`: Liste des stores à recrypter

## Sécurité

- Utilise AES-GCM 256 bits pour le chiffrement
- Dérivation de clé avec PBKDF2 (100 000 itérations)
- Vecteurs d'initialisation (IV) uniques pour chaque chiffrement
- Clés non extractibles pour plus de sécurité

## Développement

```bash
npm install    # Installation des dépendances
npm run build  # Construction (CJS, ESM, UMD)
```

## Licence

MIT
