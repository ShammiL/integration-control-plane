import ballerina/crypto;
import ballerina/lang.array;
import ballerina/toml;

// --- TOML Reader / Writer (delegated to ballerina/toml) ---

function readTomlFile(string filePath) returns map<json>|error {
    return toml:readFile(filePath);
}

function writeTomlFile(string filePath, map<json> content) returns error? {
    check toml:writeFile(filePath, content);
}

// --- Nested Key Navigation ---

function getNestedValue(map<json> content, string key) returns json|error {
    string[] parts = re `\.`.split(key);
    json current = content;

    foreach string part in parts {
        if current is map<json> {
            json? val = current[part];
            if val is () {
                return error(string `Key not found: ${key}`);
            }
            current = val;
        } else {
            return error(string `Invalid key path: ${key}`);
        }
    }
    return current;
}

function setNestedValue(map<json> content, string key, json value) returns error? {
    string[] parts = re `\.`.split(key);
    map<json> current = content;

    foreach int i in 0 ..< parts.length() - 1 {
        string part = parts[i];
        if !current.hasKey(part) {
            map<json> newMap = {};
            current[part] = newMap;
        }
        json next = current[part];
        if next is map<json> {
            current = next;
        } else {
            return error(string `Cannot create nested path for key: ${key}`);
        }
    }
    current[parts[parts.length() - 1]] = value;
}

// --- Output Paths ---

function getOutputPath(string inputPath) returns string {
    int? dotIndex = inputPath.lastIndexOf(".");
    if dotIndex is int {
        return inputPath.substring(0, dotIndex) + "_encrypted" + inputPath.substring(dotIndex);
    }
    return inputPath + "_encrypted";
}

// For rotate: strip an existing _encrypted suffix so that
// config_encrypted.toml -> config_rotated.toml (not config_encrypted_rotated.toml).
function getRotatedOutputPath(string inputPath) returns string {
    int? dotIndex = inputPath.lastIndexOf(".");
    if dotIndex is int {
        string name = inputPath.substring(0, dotIndex);
        string ext = inputPath.substring(dotIndex);
        string base = name.endsWith("_encrypted")
            ? name.substring(0, name.length() - 10)
            : name;
        return base + "_rotated" + ext;
    }
    return inputPath + "_rotated";
}


// --- Decryption Utility ---

# Decrypts a Base64-encoded RSA-encrypted value back to the original plaintext string.
# Intended for import by the ICP server to decrypt config values at startup.
#
# + encryptedBase64Value - the Base64-encoded ciphertext produced by the encrypt command
# + privateKeyPath       - path to the PKCS#8 RSA private key PEM file
# + passphrase           - passphrase protecting the private key; "" for unprotected keys
# + return               - the original plaintext string, or an error
public function decrypt(string encryptedBase64Value,
                        string privateKeyPath = DEFAULT_PRIVATE_KEY_PATH,
                        string passphrase = "") returns string|error {
    crypto:PrivateKey privateKey = passphrase == ""
        ? check crypto:decodeRsaPrivateKeyFromKeyFile(privateKeyPath)
        : check crypto:decodeRsaPrivateKeyFromKeyFile(privateKeyPath, keyPassword = passphrase);
    return check decryptWithKey(encryptedBase64Value, privateKey);
}

// Internal: decrypts using an already-loaded PrivateKey.
// Used by the rotate path to avoid re-reading the key file for each value.
function decryptWithKey(string encryptedBase64Value, crypto:PrivateKey privateKey) returns string|error {
    byte[] encryptedBytes = check array:fromBase64(encryptedBase64Value);
    byte[] decryptedBytes = check crypto:decryptRsaEcb(encryptedBytes, privateKey, crypto:PKCS1);
    return check string:fromBytes(decryptedBytes);
}