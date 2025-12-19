# REMÉDIATION - SQL Injection Error-Based (Member Search)

## 📋 Informations sur la vulnérabilité

- **Type**: SQL Injection Error-Based
- **Page affectée**: `http://192.168.10.146/?page=member`
- **Paramètre vulnérable**: `id`
- **Niveau de criticité**: 🔴 CRITIQUE
- **Impact**: Accès complet à la base de données, extraction de données sensibles

---

## 🔍 Description de la faille

La page Members permet de rechercher un membre par son ID. Le paramètre `id` est directement injecté dans une requête SQL sans validation ni échappement, permettant à un attaquant d'exécuter des requêtes SQL arbitraires.

### Exploitation réussie

```sql
-- Requête normale
id=1

-- Test d'injection
id=1'
Résultat: Erreur SQL révélée

-- Extraction de données
id=1 UNION SELECT Commentaire,countersign FROM Member_Sql_Injection.users
Résultat: Extraction de hashes de mots de passe
```

---

## 💻 Code vulnérable (AVANT)

```php
<?php
// ❌ CODE VULNÉRABLE - NE PAS UTILISER

// Récupération du paramètre sans validation
$id = $_GET['id'];

// Requête SQL avec concaténation directe
$query = "SELECT user_id, first_name, last_name
          FROM users
          WHERE user_id = '" . $id . "'";

// Exécution de la requête
$result = mysqli_query($conn, $query);

// Affichage des résultats
if ($row = mysqli_fetch_assoc($result)) {
    echo "ID: " . $row['user_id'] . "<br>";
    echo "First name: " . $row['first_name'] . "<br>";
    echo "Surname: " . $row['last_name'];
}
?>
```

### Problèmes identifiés:
1. ❌ Pas de validation du paramètre `id`
2. ❌ Concaténation directe dans la requête SQL
3. ❌ Messages d'erreur SQL affichés à l'utilisateur
4. ❌ Pas d'échappement des caractères spéciaux
5. ❌ Pas de typage strict (string au lieu de int)

---

## ✅ Code sécurisé (APRÈS)

### Solution 1: Requêtes préparées avec PDO (RECOMMANDÉ)

```php
<?php
// ✅ CODE SÉCURISÉ - RECOMMANDÉ

try {
    // Connexion PDO
    $pdo = new PDO(
        "mysql:host=localhost;dbname=Member_Sql_Injection;charset=utf8mb4",
        "username",
        "password",
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false, // Vraies requêtes préparées
        ]
    );

    // Validation du paramètre
    if (!isset($_GET['id']) || !ctype_digit($_GET['id'])) {
        throw new Exception("ID invalide");
    }

    $id = (int)$_GET['id']; // Conversion en entier

    // Requête préparée avec placeholder
    $stmt = $pdo->prepare("
        SELECT user_id, first_name, last_name
        FROM users
        WHERE user_id = :id
        LIMIT 1
    ");

    // Liaison du paramètre avec typage strict
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);

    // Exécution
    $stmt->execute();

    // Récupération sécurisée
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row) {
        // Échappement HTML pour la sortie
        echo "ID: " . htmlspecialchars($row['user_id'], ENT_QUOTES, 'UTF-8') . "<br>";
        echo "First name: " . htmlspecialchars($row['first_name'], ENT_QUOTES, 'UTF-8') . "<br>";
        echo "Surname: " . htmlspecialchars($row['last_name'], ENT_QUOTES, 'UTF-8');
    } else {
        echo "Aucun membre trouvé.";
    }

} catch (PDOException $e) {
    // Ne jamais afficher l'erreur SQL en production
    error_log("Erreur SQL: " . $e->getMessage());
    echo "Une erreur est survenue. Veuillez réessayer plus tard.";
} catch (Exception $e) {
    echo htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
}
?>
```

### Solution 2: Requêtes préparées avec MySQLi

```php
<?php
// ✅ CODE SÉCURISÉ - Alternative MySQLi

// Connexion MySQLi
$conn = new mysqli("localhost", "username", "password", "Member_Sql_Injection");

if ($conn->connect_error) {
    error_log("Erreur de connexion: " . $conn->connect_error);
    die("Erreur de connexion à la base de données.");
}

// Validation stricte
if (!isset($_GET['id']) || !filter_var($_GET['id'], FILTER_VALIDATE_INT)) {
    die("ID invalide");
}

$id = (int)$_GET['id'];

// Requête préparée
$stmt = $conn->prepare("
    SELECT user_id, first_name, last_name
    FROM users
    WHERE user_id = ?
    LIMIT 1
");

if (!$stmt) {
    error_log("Erreur de préparation: " . $conn->error);
    die("Erreur système.");
}

// Liaison du paramètre (i = integer)
$stmt->bind_param("i", $id);

// Exécution
$stmt->execute();

// Récupération du résultat
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    echo "ID: " . htmlspecialchars($row['user_id'], ENT_QUOTES, 'UTF-8') . "<br>";
    echo "First name: " . htmlspecialchars($row['first_name'], ENT_QUOTES, 'UTF-8') . "<br>";
    echo "Surname: " . htmlspecialchars($row['last_name'], ENT_QUOTES, 'UTF-8');
} else {
    echo "Aucun membre trouvé.";
}

$stmt->close();
$conn->close();
?>
```

---

## 🛡️ Mesures de sécurité additionnelles

### 1. Configuration de la base de données

```sql
-- Créer un utilisateur avec privilèges limités
CREATE USER 'webapp_user'@'localhost' IDENTIFIED BY 'strong_password_here';

-- Donner uniquement les permissions nécessaires
GRANT SELECT ON Member_Sql_Injection.users TO 'webapp_user'@'localhost';

-- NE PAS donner les permissions suivantes:
-- REVOKE DROP, CREATE, ALTER, DELETE ON *.* FROM 'webapp_user'@'localhost';

-- Interdire l'accès à information_schema
REVOKE SELECT ON information_schema.* FROM 'webapp_user'@'localhost';

FLUSH PRIVILEGES;
```

### 2. Configuration PHP (php.ini)

```ini
; Désactiver l'affichage des erreurs en production
display_errors = Off
log_errors = On
error_log = /var/log/php/error.log

; Activer les exceptions pour MySQL
mysqli.report_mode = MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT
```

### 3. Validation côté serveur

```php
<?php
/**
 * Fonction de validation pour les IDs
 */
function validateUserId($id) {
    // Vérifier que c'est un entier positif
    if (!filter_var($id, FILTER_VALIDATE_INT, [
        'options' => [
            'min_range' => 1,
            'max_range' => 999999
        ]
    ])) {
        return false;
    }
    return (int)$id;
}

// Utilisation
$id = validateUserId($_GET['id'] ?? null);
if ($id === false) {
    http_response_code(400);
    die("ID invalide");
}
?>
```

### 4. Liste blanche (Whitelist)

```php
<?php
// Si vous avez un nombre limité de valeurs acceptables
$allowed_ids = [1, 2, 3, 5]; // IDs valides

$id = (int)($_GET['id'] ?? 0);

if (!in_array($id, $allowed_ids, true)) {
    die("ID non autorisé");
}

// Continuer avec la requête préparée...
?>
```

---

## 🔒 Bonnes pratiques de sécurité

### ✅ À FAIRE:

1. **Toujours utiliser des requêtes préparées** (Prepared Statements)
   - PDO ou MySQLi avec paramètres liés
   - Jamais de concaténation de strings

2. **Valider toutes les entrées utilisateur**
   - Typage strict (int, string, email, etc.)
   - Limites de longueur
   - Format attendu (regex si nécessaire)

3. **Principe du moindre privilège**
   - Compte base de données avec permissions minimales
   - Pas d'accès à `information_schema`
   - Lecture seule si possible

4. **Gestion des erreurs**
   - Ne jamais afficher les erreurs SQL à l'utilisateur
   - Logger les erreurs dans un fichier sécurisé
   - Messages génériques pour l'utilisateur

5. **Échapper les sorties HTML**
   - Utiliser `htmlspecialchars()` pour tout affichage
   - Prévenir les XSS secondaires

6. **Limiter les résultats**
   - Toujours utiliser `LIMIT` dans les requêtes
   - Pagination pour grandes quantités de données

### ❌ À ÉVITER:

1. ❌ Concaténation SQL (`"SELECT * FROM users WHERE id = '" . $id . "'"`)
2. ❌ `mysql_*` functions (dépréciées depuis PHP 5.5)
3. ❌ `addslashes()` comme seule protection
4. ❌ `mysql_real_escape_string()` seul (préférer les requêtes préparées)
5. ❌ Afficher `mysqli_error()` ou `$e->getMessage()` en production
6. ❌ Utiliser le compte `root` pour l'application web

---

## 🧪 Tests de validation

### Test 1: Tentative d'injection basique
```
Input: 1'
Résultat attendu: Erreur "ID invalide" (pas d'erreur SQL)
```

### Test 2: UNION SELECT
```
Input: 1 UNION SELECT 1,2,3
Résultat attendu: Erreur "ID invalide"
```

### Test 3: Commentaire SQL
```
Input: 1--
Résultat attendu: Erreur "ID invalide"
```

### Test 4: ID valide
```
Input: 1
Résultat attendu: Affichage des informations du membre #1
```

### Test 5: ID négatif
```
Input: -1
Résultat attendu: Erreur "ID invalide"
```

---

## 📚 Ressources complémentaires

### Documentation officielle:
- [PHP PDO Prepared Statements](https://www.php.net/manual/fr/pdo.prepared-statements.php)
- [MySQLi Prepared Statements](https://www.php.net/manual/fr/mysqli.quickstart.prepared-statements.php)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

### Outils de test:
- [SQLMap](https://sqlmap.org/) - Outil d'audit SQL injection
- [Burp Suite](https://portswigger.net/burp) - Proxy d'interception
- [OWASP ZAP](https://www.zaproxy.org/) - Scanner de vulnérabilités

---

## ✅ Checklist de remédiation

- [ ] Remplacer les requêtes concaténées par des requêtes préparées
- [ ] Valider et typer tous les paramètres d'entrée
- [ ] Créer un utilisateur MySQL avec privilèges limités
- [ ] Désactiver l'affichage des erreurs en production
- [ ] Configurer le logging des erreurs
- [ ] Ajouter `LIMIT 1` aux requêtes
- [ ] Échapper toutes les sorties HTML
- [ ] Tester avec des payloads SQL injection
- [ ] Vérifier les logs d'erreurs
- [ ] Former l'équipe de développement

---

**Dernière mise à jour**: 2025-12-19
**Statut**: ✅ Remédiation complète
