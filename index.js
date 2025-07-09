// index.js (COMPLET ET CORRIGÉ)
require('dotenv').config();
const { TronWeb } = require('tronweb');
const fs = require('fs');
const express = require('express');
// La ligne ci-dessous n'est plus nécessaire car db.js s'en occupe
// const mysql = require('mysql2/promise'); 
const session = require('express-session');
const bcrypt = require('bcrypt');
const axios = require('axios');
const multer = require('multer');
const path = require('path');
const db = require('./db'); // Maintenant, db est déjà promisifié
const crypto = require('crypto');
const chalk = require('chalk');
let cachedTrxRateInfo = { rate: 0, lastFetched: 0 };
const CACHE_DURATION = 5 * 60 * 1000;

const tronWeb = new TronWeb({ fullHost: 'https://api.trongrid.io', headers: { "TRON-PRO-API-KEY": "c04fc1f5-5e66-41c2-a00a-70b4e368614f" } });
const storage = multer.diskStorage({ destination: (req, file, cb) => cb(null, 'public/uploads/'), filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`) });
const upload = multer({ storage, limits: { fileSize: 5000000 }, fileFilter: (req, file, cb) => file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Images seulement!')) });
if (!fs.existsSync('public/uploads')) fs.mkdirSync('public/uploads', { recursive: true });

const app = express();
const TRON_ADDRESS = process.env.TRON_ADDRESS ;
const TRON_API_KEY = process.env.TRON_API_KEY ;


function generateReferralCode(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

async function createNotification(userId, message, type = 'info') { try { await db.query('INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)', [userId, message, type]); } catch (e) { console.error(e); } }
function checkAuth(req, res, next) { if (!req.session.user_id) return res.redirect('/login'); next(); }

// Dans index.js, à côté de votre fonction checkAuth
function checkAdmin(req, res, next) {
    if (!req.session.user_id) {
        return res.redirect('/login');
    }
    if (req.session.user_role !== 'admin') {
        return res.status(403).send('Accès non autorisé');
    }
    next();
}

// Dans index.js, avec vos autres fonctions (comme generateReferralCode)

/**
 * Envoie un montant de TRX à une adresse spécifiée.
 * @param {string} toAddress L'adresse TRON du destinataire.
 * @param {number} amountFcf Le montant en FCFA à envoyer.
 * @returns {Promise<{success: boolean, txHash?: string, error?: string}>} Un objet indiquant le succès et le hash de la transaction, ou l'échec et l'erreur.
 */
async function sendTrx(toAddress, amountFcf) {
    console.log(`[PAIEMENT] Initialisation du retrait de ${amountFcf} FCFA vers ${toAddress}`);
    try {
        // Étape A : Obtenir le taux de change actuel
        const trxRate = await getTrxRate();
        if (trxRate <= 0) {
            throw new Error("Taux de change TRX invalide ou nul.");
        }

        // Étape B : Calculer le montant exact à envoyer
        const amountTrx = parseFloat((amountFcf / trxRate).toFixed(6));
        const amountSun = Math.floor(amountTrx * 1_000_000); // Conversion en SUN (plus petite unité)

        // Étape C : Charger la clé privée de manière sécurisée
        const privateKey = process.env.TRON_PRIVATE_KEY;
        if (!privateKey) {
            throw new Error("Clé privée TRON non configurée sur le serveur (.env).");
        }
        
        // Étape D : Initialiser TronWeb avec la clé pour pouvoir signer
        const tronWebWithKey = new TronWeb({
            fullHost: 'https://api.trongrid.io',
            headers: { "TRON-PRO-API-KEY": TRON_API_KEY },
            privateKey: privateKey
        });

        // Étape E : Construire, Signer et Envoyer la transaction
        console.log(`[PAIEMENT] Envoi de ${amountTrx} TRX...`);
        const transaction = await tronWebWithKey.transactionBuilder.sendTrx(toAddress, amountSun, TRON_ADDRESS);
        const signedTx = await tronWebWithKey.trx.sign(transaction);
        const receipt = await tronWebWithKey.trx.sendRawTransaction(signedTx);

        // Étape F : Vérifier le résultat
        if (receipt.result === true) {
            console.log(`[PAIEMENT] Succès ! Hash: ${receipt.txid}`);
            return { success: true, txHash: receipt.txid };
        } else {
            const errorMessage = receipt.message ? Buffer.from(receipt.message, 'hex').toString() : 'Échec de la transaction sans message.';
            throw new Error(errorMessage);
        }

    } catch (error) {
        console.error(`[PAIEMENT] Erreur critique lors de l'envoi de TRX: ${error.message}`);
        return { success: false, error: error.message };
    }
}

async function processUserPayouts(userId) {
    const [investmentsToPay] = await db.query(`SELECT id, expected_return_frs FROM investments WHERE user_id = ? AND status = 'active' AND payout_date <= NOW()`,[userId]);
    for (const inv of investmentsToPay) {
        await db.query(`UPDATE investments SET status = 'completed' WHERE id = ?`, [inv.id]);
        await db.query(`UPDATE users SET balance_fcf = balance_fcf + ? WHERE id = ?`, [inv.expected_return_frs, userId]);
        await createNotification(userId, `Gains de ${inv.expected_return_frs} FCFA reçus pour un investissement.`, 'success');
    }
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: 'VOTRE_SECRET_TRES_COMPLIQUE', resave: false, saveUninitialized: false, cookie: { secure: false } }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/', checkAuth, async (req, res) => { try { const [[user]] = await db.query('SELECT * FROM users WHERE id = ?', [req.session.user_id]); if (!user) return req.session.destroy(() => res.redirect('/login')); res.render('index', { isConnected: true, username: user.username, email: user.email }); } catch (e) { res.redirect('/login'); }});
// Dans index.js

app.get('/confirmation', checkAuth, async (req, res) => {
    try {
        // On récupère l'ID depuis les paramètres de l'URL (?investmentId=...)
        const { investmentId } = req.query;
        const userId = req.session.user_id;

        // Sécurité : si aucun ID n'est passé dans l'URL, on redirige à l'accueil.
        if (!investmentId) {
            return res.redirect('/'); 
        }

        // On cherche l'investissement dans la BDD en s'assurant qu'il appartient bien à l'utilisateur
        const sql = `
            SELECT plan_name, amount_invested_frs, expected_return_frs, transaction_hash 
            FROM investments 
            WHERE id = ? AND user_id = ?
        `;
        const [[investment]] = await db.query(sql, [investmentId, userId]);

        // Sécurité : si on ne trouve rien, ou que ça n'appartient pas au bon utilisateur, on redirige.
        if (!investment) {
            return res.redirect('/');
        }

        // Si tout est bon, on affiche la page 'confirmation.ejs' en lui passant les données
        res.render('confirmation', { investment: investment });

    } catch (error) {
        console.error("Erreur sur la page de confirmation :", error);
        res.redirect('/'); // En cas d'erreur serveur, on redirige à l'accueil.
    }
});
app.get('/login', (req, res) => res.render('login', { error: null }));
app.get('/register', (req, res) => {
    const refCode = req.query.ref || '';
    res.render('register', { refCode: refCode, error: null }); 
});
app.get('/invest', checkAuth, (req, res) => res.render('invest'));
app.get('/logout', checkAuth, (req, res) => req.session.destroy(() => res.redirect('/login')));

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [[user]] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (!user || !(await bcrypt.compare(password, user.password))) return res.render('login', { error: 'Identifiants incorrects' });
        req.session.user_id = user.id;
        req.session.username = user.username;
        req.session.user_role = user.role; // <-- AJOUTEZ CETTE LIGNE
         req.session.save(err => {
            if (err) return res.status(500).send('Erreur session');
            res.redirect('/');
        });
    } catch (e) { res.status(500).send('Erreur serveur'); }
});

app.get('/contact', (req, res) => {
     console.log("LA ROUTE /contact A BIEN ÉTÉ ATTEINTE !");
    res.render('contact'); 
});

app.get('/about', (req, res) => {
    res.render('about'); 
});

// ROUTE /register CORRIGÉE - plus besoin de .promise()
app.post('/register', async (req, res) => {
    const { username, email, password, refCode } = req.body;

    if (!username || !email || !password) {
        return res.render('register', {
            refCode: refCode,
            error: "Veuillez remplir tous les champs."
        });
    }

    try {
        let parrainId = null;
        if (refCode) {
            // CORRECTION ICI: db.query() au lieu de db.promise().query()
            const [parrains] = await db.query('SELECT id FROM users WHERE invitation_code = ?', [refCode]);
            if (parrains.length > 0) {
                parrainId = parrains[0].id;
                console.log(`Utilisateur parrain trouvé : ID = ${parrainId}`);
            } else {
                console.log(`Code de parrainage "${refCode}" invalide ou non trouvé.`);
            }
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        let newInvitationCode;
        let isCodeUnique = false;
        while (!isCodeUnique) {
            newInvitationCode = generateReferralCode();
            // CORRECTION ICI
            const [existingUser] = await db.query('SELECT id FROM users WHERE invitation_code = ?', [newInvitationCode]);
            if (existingUser.length === 0) {
                isCodeUnique = true;
            }
        }

        const sql = 'INSERT INTO users (username, email, password, invitation_code, referred_by) VALUES (?, ?, ?, ?, ?)';
        // CORRECTION ICI
        const [result] = await db.execute(sql, [username, email, hashedPassword, newInvitationCode, parrainId]);

        console.log('Nouvel utilisateur enregistré avec succès ! ID:', result.insertId);
        
        
// Création d'une notification de bienvenue améliorée
            const welcomeMessage = `Bienvenue, ${username} ! Votre compte est prêt. Trouvez votre lien de parrainage unique dans votre profil et commencez à gagner 1000 FCFA pour chaque ami invité.`;
            await createNotification(result.insertId, welcomeMessage, 'welcome');
        
        res.redirect('/login');

    } catch (error) {
        console.error("Erreur lors de l'inscription :", error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.render('register', {
                refCode: refCode,
                error: "Cette adresse e-mail est déjà utilisée."
            });
        }
        
        return res.render('register', {
            refCode: refCode,
            error: "Une erreur est survenue sur le serveur. Veuillez réessayer."
        });
    }
});


// Dans index.js, avec vos autres routes GET
app.get('/admin/withdrawals', checkAdmin, async (req, res) => {
    try {
        const [pendingWithdrawals] = await db.query(
            `SELECT w.id, u.username, w.amount_fcf, w.wallet_address, w.created_at 
             FROM withdrawals w
             JOIN users u ON w.user_id = u.id
             WHERE w.status = 'pending'
             ORDER BY w.created_at ASC`
        );
        
        res.render('admin-withdrawals', { withdrawals: pendingWithdrawals });

    } catch (error) {
        console.error("Erreur chargement des retraits admin:", error);
        res.status(500).send("Erreur serveur");
    }
});

app.get('/payment', checkAuth, async (req, res) => {
    // Votre code de base est conservé
    const { title, price, 'return': returnAmount, duration } = req.query;

    try {
        // Votre code de base est conservé
        const duration_days = duration ? parseInt(duration, 10) : 0;
        
        if (duration_days <= 0) {
            console.error("Durée d'investissement invalide reçue :", duration);
            return res.status(400).send("Durée d'investissement invalide.");
        }

        const payoutDate = new Date();
        payoutDate.setDate(payoutDate.getDate() + duration_days);

        // --- AJOUT NÉCESSAIRE POUR CORRIGER L'ERREUR ---
        // On calcule la valeur manquante pour la colonne 'amount_invested_trx'
        const priceFcf = parseFloat(price);
        if (isNaN(priceFcf)) {
            // Sécurité pour s'assurer que le prix est un nombre
            return res.status(400).send("Prix d'investissement invalide.");
        }
        
        const trxRate = await getTrxRate();
        if (trxRate <= 0) {
            return res.status(500).send("Impossible de récupérer le taux de change pour le moment.");
        }
        const amountTrx = (priceFcf / trxRate).toFixed(6);
        // --- FIN DE L'AJOUT NÉCESSAIRE ---


        // Votre requête SQL est maintenant modifiée pour inclure la nouvelle colonne
        const sql = `
            INSERT INTO investments (
                user_id, plan_name, amount_invested_frs, 
                amount_invested_trx, -- Colonne ajoutée
                expected_return_frs, status, payout_date, duration_days
            ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
        `;

        // Votre tableau de valeurs est maintenant modifié pour inclure la nouvelle valeur
        const values = [
            req.session.user_id, 
            title, 
            price, 
            amountTrx, // Valeur ajoutée
            returnAmount, 
            payoutDate, 
            duration_days
        ];
        
        const [result] = await db.execute(sql, values);
        
        // Votre code de base pour le rendu est conservé
        res.render('payment', { 
            title, 
            price, 
            returnAmount, 
            walletAddress: TRON_ADDRESS, 
            investmentId: result.insertId 
        });

    } catch (e) {
        // Votre gestion d'erreur de base est conservée
        console.error("Erreur dans la route /payment :", e);
        res.status(500).send('Erreur serveur');
    }
});



// VERSION DE DÉBOGAGE ULTIME
async function getTrxRate() {
    const now = Date.now();
    console.log(chalk.cyan('[TAUX DEBUG] Début de la fonction getTrxRate.'));

    if (cachedTrxRateInfo.rate > 0 && (now - cachedTrxRateInfo.lastFetched) < CACHE_DURATION) {
        console.log(chalk.green(`[TAUX DEBUG] CACHE HIT : Taux trouvé en cache (${cachedTrxRateInfo.rate}). Pas d'appel API.`));
        return cachedTrxRateInfo.rate;
    }

    console.log(chalk.yellow("[TAUX DEBUG] CACHE MISS : Le cache est vide ou expiré. Préparation de l'appel API..."));
    try {
        const apiUrl = 'https://api.coingecko.com/api/v3/simple/price?ids=tron&vs_currencies=usd';
        console.log(chalk.yellow(`[TAUX DEBUG] Tentative d'appel à l'URL : ${apiUrl}`));

        const response = await axios.get(apiUrl);

        console.log(chalk.green('[TAUX DEBUG] API SUCCESS : Réponse reçue de CoinGecko.'));

        if (!response.data || !response.data.tron || !response.data.tron.usd) {
            console.error(chalk.red('[TAUX DEBUG] Erreur : Format de réponse API invalide.'));
            throw new Error("Réponse invalide de l'API CoinGecko.");
        }

        const usdRate = response.data.tron.usd;
        const newRate = usdRate * 600;
        
        cachedTrxRateInfo = { rate: newRate, lastFetched: now };
        console.log(chalk.blue.bold(`[TAUX DEBUG] Nouveau taux mis en cache : ${newRate}`));
        return newRate;

    } catch (error) {
        console.error(chalk.red.bold('[TAUX DEBUG] L\'APPEL API A ÉCHOUÉ. Erreur interceptée :'), error.message);
        
        // On affiche les détails de l'erreur si disponibles (très important)
        if (error.response) {
            console.error(chalk.red.bold('[TAUX DEBUG] Détails de l\'erreur :'), `Statut ${error.response.status}`, error.response.data);
        }

        if (cachedTrxRateInfo.rate > 0) {
            console.warn(chalk.yellow('[TAUX DEBUG] L\'API a échoué, mais un ancien cache existe. Utilisation de l\'ancien taux.'));
            return cachedTrxRateInfo.rate;
        }

        const fallbackRate = 80; // Un taux de secours raisonnable pour 1 USD = X FCFA -> 1 TRX = Y FCFA
        console.warn(chalk.bgRed.white.bold(`[TAUX DEBUG] FATAL : L'API a échoué et aucun cache n'existe. Utilisation du taux de secours fixe : ${fallbackRate}`));
        return fallbackRate;
    }
}

const REFERRAL_BONUS_AMOUNT = 1000;

// ROUTE processReferralBonus CORRIGÉE - plus besoin de .promise()
async function processReferralBonus(filleulId, dbConnection) {
    console.log(`[Parrainage] Vérification du bonus pour le filleul ID: ${filleulId}`);
    
    try {
        // CORRECTION ICI : dbConnection est déjà promisifié
        const [filleuls] = await dbConnection.query('SELECT referred_by, referral_bonus_paid FROM users WHERE id = ?', [filleulId]);

        if (filleuls.length === 0) {
            console.log(`[Parrainage] Filleul ID ${filleulId} non trouvé.`);
            return;
        }

        const filleul = filleuls[0];
        const parrainId = filleul.referred_by;
        const bonusAlreadyPaid = filleul.referral_bonus_paid;

        if (parrainId && !bonusAlreadyPaid) {
            console.log(`[Parrainage] Conditions remplies. Filleul ID: ${filleulId}, Parrain ID: ${parrainId}`);

            // CORRECTION ICI
            const connection = await dbConnection.getConnection();
            await connection.beginTransaction();

            try {
                await connection.execute('UPDATE users SET balance_fcf = balance_fcf + ? WHERE id = ?', [REFERRAL_BONUS_AMOUNT, parrainId]);
                await connection.execute('UPDATE users SET referral_bonus_paid = TRUE WHERE id = ?', [filleulId]);
                const notificationMessage = `Félicitations ! Un de vos filleuls a investi. Vous avez reçu une prime de ${REFERRAL_BONUS_AMOUNT} FCFA.`;
                await createNotification(parrainId, notificationMessage, 'success');
                await connection.commit();

            } catch (error) {
                await connection.rollback();
                throw error;
            } finally {
                connection.release();
            }
        }
    } catch (error) {
        console.error(`[Parrainage] Erreur grave lors du traitement du bonus pour le filleul ID ${filleulId}:`, error);
    }
}

// ROUTE /check-payment CORRIGÉE - plus besoin de .promise()
app.get('/check-payment', checkAuth, async (req, res) => {
    const { expectedAmount, investmentId } = req.query;
    const userId = req.session.user_id;
    const parsedExpectedAmount = parseFloat(expectedAmount);

    if (!userId || isNaN(parsedExpectedAmount) || !investmentId) {
        return res.status(400).json({ error: 'Données invalides.' });
    }
    
    const minimumAcceptedAmount = parsedExpectedAmount * 0.99;

    try {
        const response = await axios.get(`https://api.trongrid.io/v1/accounts/${TRON_ADDRESS}/transactions`, { 
            params: { limit: 50, only_to: true, min_timestamp: Date.now() - (20 * 60 * 1000) }, 
            headers: { 'TRON-PRO-API-KEY': TRON_API_KEY } 
        });

        if (!response.data.success || !Array.isArray(response.data.data)) {
            return res.status(500).json({ error: 'Réponse de l\'API Tron invalide' });
        }

        for (const tx of response.data.data) {
            const amountTRX = tx.raw_data.contract[0].parameter.value.amount / 1_000_000;
            if (amountTRX >= minimumAcceptedAmount) {
                
                // CORRECTION ICI
                const [existing] = await db.query('SELECT id FROM investments WHERE transaction_hash = ?', [tx.txID]);
                if (existing.length > 0) {
                    continue;
                }

                // CORRECTION ICI
                const [userInvestments] = await db.query('SELECT COUNT(id) as count FROM investments WHERE user_id = ? AND status != ?', [userId, 'pending']);
                const isFirstInvestment = userInvestments[0].count === 0;

                // CORRECTION ICI
                await db.execute(`UPDATE investments SET status = 'active', transaction_hash = ? WHERE id = ? AND user_id = ?`, [tx.txID, investmentId, userId]);
                await createNotification(userId, `Votre investissement a été confirmé.`, 'success');

                if (isFirstInvestment) {
                    await processReferralBonus(userId, db);
                }
                
                return res.json({ paid: true });
            }
        }
        
        res.json({ paid: false });

    } catch (e) { 
        console.error("Erreur critique dans /check-payment:", e);
        res.status(500).json({ error: 'Erreur serveur critique' }); 
    }
});

// Le reste de vos routes reste inchangé car elles utilisent déjà la bonne syntaxe
app.post('/process-payouts', checkAuth, async (req, res) => { try { await processUserPayouts(req.session.user_id); res.json({ success: true }); } catch(e) { res.status(500).json({success: false})} });
// Dans index.js
app.get('/profile-data', checkAuth, async (req, res) => { 
    try { 
        // --- MODIFICATION DE LA REQUÊTE ---
        // On sélectionne les champs nécessaires et on utilise "AS" pour renommer la colonne
        const sql = `
            SELECT 
                username, 
                email, 
                wallet_address, 
                balance_fcf, 
                profile_image_url,
                invitation_code AS referral_code -- C'est la correction clé !
            FROM users 
            WHERE id = ?
        `;
        const [[user]] = await db.query(sql, [req.session.user_id]);
        
        // Maintenant, l'objet "user" contiendra une propriété "referral_code"
        res.json({ success: true, user }); 

    } catch(e){ 
        console.error("Erreur dans /profile-data:", e); // Ajout d'un log pour le débogage
        res.status(500).json({success: false})
    }
});
app.get('/user-investments', checkAuth, async (req, res) => {
    try {
        const [investments] = await db.query(
            `SELECT id, plan_name, amount_invested_frs, expected_return_frs, status, date_invested, payout_date 
             FROM investments WHERE user_id = ? ORDER BY date_invested DESC`,
            [req.session.user_id]
        );
        console.log(chalk.bgMagenta.bold('\n[BACKEND] Données d\'investissement envoyées au client :'));
        console.log(investments);
        res.json({ success: true, investments: investments });
    } catch (error) {
        console.error("Erreur API /user-investments:", error);
        res.status(500).json({ success: false, error: 'Erreur serveur.' });
    }
});
app.get('/notifications', checkAuth, async (req, res) => { try { const [notifications] = await db.query('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.session.user_id]); await db.query('UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0', [req.session.user_id]); res.json({ success: true, notifications }); } catch(e){ res.status(500).json({success: false})}});
app.post('/update-profile', checkAuth, async (req, res) => { const { username, email, wallet_address } = req.body; try { await db.query('UPDATE users SET username = ?, email = ?, wallet_address = ? WHERE id = ?', [username, email, wallet_address, req.session.user_id]); req.session.username = username; res.json({ success: true, message: 'Profil mis à jour !' }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur de mise à jour.' }); } });
// Remplacez votre route /request-withdrawal existante par celle-ci

app.post('/request-withdrawal', checkAuth, async (req, res) => {
    const userId = req.session.user_id;
    const DAILY_LIMIT = 2500; // Limite de retrait journalière en FCFA

    try {
        // --- Étape 1 : Récupérer les informations de l'utilisateur ---
        const [[user]] = await db.query('SELECT balance_fcf, wallet_address FROM users WHERE id = ?', [userId]);

        // Vérification de base : l'utilisateur a-t-il une adresse de retrait ?
        if (!user.wallet_address) {
            return res.status(400).json({ success: false, error: 'Veuillez enregistrer une adresse de retrait dans votre profil.' });
        }
        
        // Vérification de base : le solde est-il positif ?
        if (user.balance_fcf <= 0) {
            return res.status(400).json({ success: false, error: 'Solde insuffisant pour un retrait.' });
        }

        // --- Étape 2 : Vérifier la limite de retrait journalière ---
        const [rows] = await db.query(
            "SELECT SUM(amount_fcf) as total_withdrawn_today FROM withdrawals WHERE user_id = ? AND DATE(created_at) = CURDATE() AND status != 'failed'",
            [userId]
        );
        
        const totalWithdrawnToday = rows[0].total_withdrawn_today || 0;
        
        if (totalWithdrawnToday >= DAILY_LIMIT) {
            return res.status(403).json({ success: false, error: 'Vous avez atteint votre limite de retrait de 2500 FCFA pour aujourd\'hui.' });
        }

        // --- Étape 3 : Calculer le montant exact du retrait ---
        const remainingAllowance = DAILY_LIMIT - totalWithdrawnToday;
        // Le montant du retrait est le minimum entre le solde de l'utilisateur et ce qu'il lui reste à retirer aujourd'hui
        const amountToWithdraw = Math.min(user.balance_fcf, remainingAllowance);

        if (amountToWithdraw <= 0) {
             return res.status(400).json({ success: false, error: 'Le montant retirable est nul ou négatif.' });
        }
        
        // --- Étape 4 : Utiliser une transaction pour garantir la cohérence ---
        const connection = await db.getConnection();
        await connection.beginTransaction();

        try {
            // Déduire le montant du solde de l'utilisateur
            await connection.query('UPDATE users SET balance_fcf = balance_fcf - ? WHERE id = ?', [amountToWithdraw, userId]);

            // Enregistrer la demande de retrait dans la nouvelle table
            await connection.query(
                'INSERT INTO withdrawals (user_id, amount_fcf, wallet_address, status) VALUES (?, ?, ?, ?)', 
                [userId, amountToWithdraw, user.wallet_address, 'pending']
            );

            // Valider la transaction
            await connection.commit();

        } catch (transactionError) {
            // En cas d'erreur, annuler toutes les opérations
            await connection.rollback();
            console.error("Erreur de transaction lors de la demande de retrait:", transactionError);
            return res.status(500).json({ success: false, error: 'Erreur lors de l\'enregistrement de la demande.' });
        } finally {
            // Toujours libérer la connexion
            connection.release();
        }

        // --- Étape 5 : Notifier l'utilisateur ---
        await createNotification(userId, `Votre demande de retrait de ${amountToWithdraw.toLocaleString('fr-FR')} FCFA est en cours de traitement.`, 'info');

        // Envoyer la réponse de succès au client
        res.json({ success: true, message: `Demande de retrait de ${amountToWithdraw.toLocaleString('fr-FR')} FCFA enregistrée.` });

    } catch (e) {
        console.error("Erreur critique dans /request-withdrawal:", e);
        res.status(500).json({ success: false, error: 'Erreur serveur.' });
    }
});

// Dans index.js, avec vos autres routes POST

app.post('/admin/process-withdrawal', checkAdmin, async (req, res) => {
    const { withdrawalId, action } = req.body;

    if (!withdrawalId || !action) {
        return res.status(400).send("Requête invalide.");
    }

    const connection = await db.getConnection();
    await connection.beginTransaction();

    try {
        // 1. VERROUILLER LA DEMANDE pour éviter un double paiement
        const [[withdrawal]] = await connection.query("SELECT * FROM withdrawals WHERE id = ? AND status = 'pending' FOR UPDATE", [withdrawalId]);
        
        if (!withdrawal) {
            await connection.rollback();
            return res.status(404).send("Demande non trouvée ou déjà traitée.");
        }

        // 2. CAS : L'ADMIN APPROUVE
        if (action === 'approve') {
            await connection.query("UPDATE withdrawals SET status = 'processing' WHERE id = ?", [withdrawalId]);
            const paymentResult = await sendTrx(withdrawal.wallet_address, withdrawal.amount_fcf);

            if (paymentResult.success) {
                // Le paiement a réussi
                await connection.query(
                    "UPDATE withdrawals SET status = 'completed', transaction_hash = ?, processed_at = NOW() WHERE id = ?", 
                    [paymentResult.txHash, withdrawalId]
                );
                await createNotification(withdrawal.user_id, `Votre retrait de ${withdrawal.amount_fcf.toLocaleString('fr-FR')} FCFA a été traité.`, 'success');
            } else {
                // Le paiement a échoué, on rembourse l'utilisateur
                await connection.query(
                    "UPDATE withdrawals SET status = 'failed', notes = ? WHERE id = ?", 
                    [`Échec: ${paymentResult.error}`, withdrawalId]
                );
                await connection.query("UPDATE users SET balance_fcf = balance_fcf + ? WHERE id = ?", [withdrawal.amount_fcf, withdrawal.user_id]);
                await createNotification(withdrawal.user_id, `Votre retrait a échoué. Les fonds ont été retournés sur votre solde.`, 'error');
            }
        } 
        // 3. CAS : L'ADMIN REJETTE
        else if (action === 'reject') {
             await connection.query("Rejeté par l'administrateur WHERE id = ?", [withdrawalId]);
            // On rembourse l'utilisateur
            await connection.query("UPDATE users SET balance_fcf = balance_fcf + ? WHERE id = ?", [withdrawal.amount_fcf, withdrawal.user_id]);
            await createNotification(withdrawal.user_id, `Votre retrait a été rejeté. Les fonds ont été retournés sur votre solde.`, 'error');
        }

        // 4. ON VALIDE TOUTES LES OPÉRATIONS
        await connection.commit();
        res.redirect('/admin/withdrawals');

    } catch (error) {
        await connection.rollback();
        console.error("Erreur critique /admin/process-withdrawal:", error);
        res.status(500).send("Erreur serveur.");
    } finally {
        connection.release();
    }
});

// index.js

   
   app.get('/referral', async (req, res) => {
      console.log('Session sur la page /referral:', req.session);
    try {
        const [recentBonuses] = await db.query(
            `SELECT u.username, n.created_at 
             FROM notifications n JOIN users u ON n.user_id = u.id
             WHERE n.message LIKE '%prime%' ORDER BY n.created_at DESC LIMIT 5`
        );
        res.render('referral', { 
            username: req.session.username || null,
            recentBonuses: recentBonuses 
        });
    } catch (error) {
        console.error("Erreur sur la page de parrainage :", error);
        res.render('referral', { 
            username: req.session.username || null, 
            recentBonuses: [] 
        });
    }
});



// ===============================================
// ROUTE POUR ANNULER UN INVESTISSEMENT EN ATTENTE
// ===============================================
app.post('/cancel-investment', checkAuth, async (req, res) => {
    const { investmentId } = req.body;
    const userId = req.session.user_id;

    if (!investmentId) {
        return res.status(400).json({ success: false, error: 'ID de l\'investissement manquant.' });
    }

    try {
        // Pour la sécurité, on s'assure que l'investissement appartient bien à l'utilisateur
        // et qu'il est bien en statut 'pending'. On ne peut pas annuler un paiement déjà fait.
        const [result] = await db.execute(
            `DELETE FROM investments WHERE id = ? AND user_id = ? AND status = 'pending'`,
            [investmentId, userId]
        );

        // La propriété `affectedRows` nous dit si une ligne a bien été supprimée.
        if (result.affectedRows > 0) {
            console.log(`[ANNULATION] L'investissement ID ${investmentId} pour l'utilisateur ID ${userId} a été annulé avec succès.`);
            res.json({ success: true, message: 'Investissement annulé.' });
        } else {
            // Si affectedRows est 0, c'est soit que l'ID n'existe pas,
            // soit qu'il n'appartient pas à l'utilisateur,
            // soit qu'il n'est plus en statut 'pending'.
            console.warn(`[ANNULATION] Tentative d'annulation échouée pour l'investissement ID ${investmentId} par l'utilisateur ID ${userId}.`);
            res.status(404).json({ success: false, error: 'Impossible d\'annuler cet investissement. Il a peut-être déjà été payé ou n\'existe pas.' });
        }

    } catch (error) {
        console.error("Erreur critique dans /cancel-investment:", error);
        res.status(500).json({ success: false, error: 'Erreur serveur.' });
    }
});


app.post('/update-profile-picture', checkAuth, upload.single('profile_image'), async (req, res) => { if (!req.file) return res.status(400).json({ success: false, error: 'Aucun fichier.' }); const imageUrl = `/uploads/${req.file.filename}`; try { await db.query('UPDATE users SET profile_image_url = ? WHERE id = ?', [imageUrl, req.session.user_id]); res.json({ success: true, message: 'Image mise à jour.', newImageUrl: imageUrl }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur sauvegarde.' }); } });
app.delete('/notifications/:id', checkAuth, async (req, res) => { try { await db.query('DELETE FROM notifications WHERE id = ? AND user_id = ?', [req.params.id, req.session.user_id]); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur.' }); } });
app.get('/api/trx-rate', async (req, res) => { try { res.json({ rate: await getTrxRate() }); }
 catch (e) { res.status(500).json({ error: 'Impossible de récupérer le taux.' }); } });

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Serveur lancé sur http://localhost:${port}`));
