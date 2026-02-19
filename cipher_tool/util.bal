import ballerina/io;
import ballerina/crypto;
import ballerina/lang.array;

// --- TOML Reader ---

function readTomlFile(string filePath) returns map<json>|error {
    string[] lines = check io:fileReadLines(filePath);
    map<json> result = {};
    string currentTable = "";

    foreach string line in lines {
        string trimmed = line.trim();

        if trimmed == "" || trimmed.startsWith("#") {
            continue;
        }

        // Table header: [section] or [section.subsection]
        if trimmed.startsWith("[") && !trimmed.startsWith("[[") && trimmed.endsWith("]") {
            currentTable = trimmed.substring(1, trimmed.length() - 1).trim();
            continue;
        }

        // Key-value pair
        int? eqIndex = trimmed.indexOf("=");
        if eqIndex is int {
            string key = trimmed.substring(0, eqIndex).trim();
            string rawValue = trimmed.substring(eqIndex + 1).trim();
            json parsedValue = parseTomlValue(rawValue);

            if currentTable != "" {
                check setNestedValue(result, currentTable + "." + key, parsedValue);
            } else {
                result[key] = parsedValue;
            }
        }
    }

    return result;
}

function parseTomlValue(string rawValue) returns json {
    // Quoted string (double quotes)
    if rawValue.startsWith("\"") && rawValue.endsWith("\"") && rawValue.length() >= 2 {
        return rawValue.substring(1, rawValue.length() - 1);
    }
    // Quoted string (single quotes)
    if rawValue.startsWith("'") && rawValue.endsWith("'") && rawValue.length() >= 2 {
        return rawValue.substring(1, rawValue.length() - 1);
    }
    // Boolean
    if rawValue == "true" {
        return true;
    }
    if rawValue == "false" {
        return false;
    }
    // Integer
    int|error intVal = int:fromString(rawValue);
    if intVal is int {
        return intVal;
    }
    // Float
    float|error floatVal = float:fromString(rawValue);
    if floatVal is float {
        return floatVal;
    }
    // Fallback: return as-is string
    return rawValue;
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

// --- Output Path ---

function getOutputPath(string inputPath) returns string {
    int? dotIndex = inputPath.lastIndexOf(".");
    if dotIndex is int {
        return inputPath.substring(0, dotIndex) + "_encrypted" + inputPath.substring(dotIndex);
    }
    return inputPath + "_encrypted";
}

// --- TOML Writer ---

function writeTomlFile(string filePath, map<json> content) returns error? {
    string[] lines = [];
    buildTomlLines(content, lines, "");
    check io:fileWriteLines(filePath, lines);
}

function buildTomlLines(map<json> content, string[] lines, string prefix) {
    // First: write simple key-value pairs at this level
    foreach [string, json] [key, value] in content.entries() {
        if value is map<json> {
            continue; // handle tables after simple values
        }
        if value is string {
            lines.push(key + " = \"" + escapeTomlString(value) + "\"");
        } else {
            lines.push(key + " = " + value.toString());
        }
    }

    // Then: write nested tables
    foreach [string, json] [key, value] in content.entries() {
        if value is map<json> {
            string tableName = prefix == "" ? key : prefix + "." + key;
            lines.push("");
            lines.push("[" + tableName + "]");
            buildTomlLines(value, lines, tableName);
        }
    }
}

function escapeTomlString(string value) returns string {
    string result = re `\\`.replaceAll(value, "\\\\");
    result = re `"`.replaceAll(result, "\\\"");
    return result;
}

// --- Decryption Utility ---

# Decrypts a Base64-encoded RSA-encrypted value back to the original plaintext string.
#
# + encryptedBase64Value - the Base64-encoded ciphertext (as produced by the encrypt flow)
# + privateKeyPath - path to the RSA private key PEM file (defaults to the bundled key)
# + return - the decrypted plaintext string, or an error
public function decrypt(string encryptedBase64Value,
                        string privateKeyPath = DEFAULT_PRIVATE_KEY_PATH) returns string|error {
    crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyFile(privateKeyPath);
    byte[] encryptedBytes = check array:fromBase64(encryptedBase64Value);
    byte[] decryptedBytes = check crypto:decryptRsaEcb(encryptedBytes, privateKey, crypto:PKCS1);
    return check string:fromBytes(decryptedBytes);
}