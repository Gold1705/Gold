// test-tronweb.js
try {
    console.log("--- Tentative avec require('tronweb') ---");
    const tronWebModule = require('tronweb');
    console.log('Type du module importé :', typeof tronWebModule);
    console.log('Clés du module :', Object.keys(tronWebModule));

    // Essayons de voir si le constructeur est caché quelque part
    if (tronWebModule.default) {
        console.log('Module a une propriété .default');
        console.log('Type de .default :', typeof tronWebModule.default);
    }

    // Tentative d'instanciation pour voir l'erreur
    new tronWebModule();

} catch (e) {
    console.error("ERREUR:", e.message);
}