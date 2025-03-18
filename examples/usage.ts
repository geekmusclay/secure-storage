// Exemple d'utilisation de SecureStorage en TypeScript/ES Modules
import { SecureStorage } from '../src/SecureStorage';

// Interface pour notre type de données
interface UserData {
  id: number;
  name: string;
  email: string;
  preferences: {
    theme: 'light' | 'dark';
    notifications: boolean;
  };
}

async function exempleUtilisation() {
  // 1. Initialisation
  const storage = new SecureStorage('mot-de-passe-secret');

  // 2. Stockage de données
  const userData: UserData = {
    id: 1,
    name: 'Jean Dupont',
    email: 'jean@example.com',
    preferences: {
      theme: 'dark',
      notifications: true
    }
  };

  try {
    // Stocker les données
    await storage.storeEncrypted(
      'ma-base', // nom de la base IndexedDB
      'utilisateurs', // nom du store
      'user_1', // clé
      userData // données à chiffrer
    );
    console.log('Données stockées avec succès');

    // Récupérer les données
    const donnéesRécupérées = await storage.retrieveDecrypted<UserData>(
      'ma-base',
      'utilisateurs',
      'user_1'
    );
    console.log('Données récupérées:', donnéesRécupérées);

    // Changer le mot de passe (recrypte toutes les données)
    await storage.changePassword(
      'nouveau-mot-de-passe',
      'ma-base',
      ['utilisateurs']
    );
    console.log('Mot de passe changé avec succès');

  } catch (error) {
    console.error('Erreur:', error);
  }
}

// Pour une utilisation en JavaScript vanilla (via UMD), le code serait :
/*
<script src="dist/secure-storage.umd.js"></script>
<script>
  const storage = new SecureStorage('mot-de-passe-secret');
  
  async function exempleUtilisation() {
    try {
      await storage.storeEncrypted('ma-base', 'utilisateurs', 'user_1', {
        id: 1,
        name: 'Jean Dupont',
        email: 'jean@example.com',
        preferences: {
          theme: 'dark',
          notifications: true
        }
      });
      
      const données = await storage.retrieveDecrypted('ma-base', 'utilisateurs', 'user_1');
      console.log('Données récupérées:', données);
    } catch (error) {
      console.error('Erreur:', error);
    }
  }
</script>
*/

// Pour Node.js (CommonJS), le code serait :
/*
const { SecureStorage } = require('secure-storage');

const storage = new SecureStorage('mot-de-passe-secret');
// ... même utilisation que ci-dessus
*/

// Exécuter l'exemple
exempleUtilisation();
