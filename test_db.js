const db = require('./db');

async function testConnection() {
  try {
    const [rows] = await db.query('SELECT 1 + 1 AS solution');
    console.log('Connexion réussie, test:', rows[0].solution);
  } catch (err) {
    console.error('Erreur connexion DB:', err);
  }
}

testConnection();
