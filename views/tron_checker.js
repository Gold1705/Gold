const TronWeb = require('tronweb');
const pool = require('./db'); // ta connexion mysql2/promise
require('dotenv').config();

const tronWeb = new TronWeb({
  fullHost: 'https://api.trongrid.io' // nœud public
});

async function getPendingWallets() {
  const [rows] = await pool.execute(`
    SELECT u.id AS user_id, u.wallet_address, i.id AS investment_id
    FROM users u
    JOIN investments i ON u.id = i.user_id
    WHERE i.status = 'pending' AND u.wallet_address IS NOT NULL
  `);
  return rows;
}

async function checkTransactionsFor(wallet, userId, investmentId) {
  try {
    const txs = await tronWeb.trx.getTransactionsRelated(wallet, 'to');

    for (const tx of txs) {
      const txID = tx.txID;
      const status = tx.ret[0]?.contractRet;
      const contract = tx.raw_data?.contract[0];
      if (!contract || status !== 'SUCCESS') continue;

      const value = contract.parameter.value;
      const from = tronWeb.address.fromHex(value.owner_address);
      const to = tronWeb.address.fromHex(value.to_address);
      const amountTRX = value.amount / 1_000_000;

      // Vérifier si déjà traité
      const [exist] = await pool.execute(
        'SELECT id FROM transactions WHERE status = "completed" AND user_id = ? AND amount = ? AND currency = "TRX"',
        [userId, amountTRX]
      );
      if (exist.length > 0) continue;

      // Ajouter transaction
      await pool.execute(`
        INSERT INTO transactions (user_id, amount, currency, status)
        VALUES (?, ?, 'TRX', 'completed')
      `, [userId, amountTRX]);

      // Mettre à jour l'investissement
      await pool.execute(`
        UPDATE investments
        SET status = 'completed', transaction_hash = ?, amount_invested_trx = ?
        WHERE id = ?
      `, [txID, amountTRX, investmentId]);

      // Ajouter une notification
      await pool.execute(`
        INSERT INTO notifications (user_id, message, type)
        VALUES (?, ?, ?)
      `, [
        userId,
        `Paiement reçu : ${amountTRX} TRX de ${from}`,
        'paiement'
      ]);

      console.log(`✅ Paiement détecté pour user ${userId} : ${amountTRX} TRX`);
    }
  } catch (err) {
    console.error(`Erreur sur ${wallet} :`, err.message);
  }
}

async function runMonitor() {
  const wallets = await getPendingWallets();
  for (const { wallet_address, user_id, investment_id } of wallets) {
    await checkTransactionsFor(wallet_address, user_id, investment_id);
  }
}

setInterval(runMonitor, 20 * 1000);
runMonitor();
