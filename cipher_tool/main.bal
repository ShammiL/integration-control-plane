import ballerina/io;
import ballerina/crypto;

const string DEFAULT_PUBLIC_KEY_PATH = "resources/public_key.pem";
const string DEFAULT_PRIVATE_KEY_PATH = "resources/private_key.pem";

public function main(string... args) returns error? {
    if args.length() < 2 {
        io:println("Usage: bal run -- <toml_file> <key1> [key2] ... [--publicKeyPath=<path>]");
        io:println("Keys support dot notation for nested values (e.g., database.password)");
        return;
    }

    // Parse arguments: first arg is TOML file path, rest are keys or flags
    string tomlFilePath = args[0];
    string publicKeyPath = DEFAULT_PUBLIC_KEY_PATH;
    string[] keys = [];

    foreach int i in 1 ..< args.length() {
        if args[i].startsWith("--publicKeyPath=") {
            publicKeyPath = args[i].substring(16);
        } else {
            keys.push(args[i]);
        }
    }

    if keys.length() == 0 {
        io:println("Error: At least one key must be specified.");
        return;
    }

    // Read and parse the TOML file
    map<json> tomlContent = check readTomlFile(tomlFilePath);

    // Load RSA public key from certificate file
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromCertFile(publicKeyPath);

    // Encrypt each specified key's value
    map<json> encryptedContent = {};
    foreach string key in keys {
        json value = check getNestedValue(tomlContent, key);
        string strValue = value.toString();
        byte[] encrypted = check crypto:encryptRsaEcb(strValue.toBytes(), publicKey, crypto:PKCS1);
        string base64Value = encrypted.toBase64();
        check setNestedValue(encryptedContent, key, base64Value);
        io:println(string `Encrypted key: ${key}`);
    }

    // Write encrypted content to output TOML file
    string outputPath = getOutputPath(tomlFilePath);
    check writeTomlFile(outputPath, encryptedContent);
    io:println(string `Encrypted values written to: ${outputPath}`);

    // Verify decryption round-trip
    io:println("\n--- Decryption verification ---");
    foreach string key in keys {
        json encVal = check getNestedValue(encryptedContent, key);
        string decrypted = check decrypt(encVal.toString());
        io:println(string `${key}: ${decrypted}`);
    }
}

