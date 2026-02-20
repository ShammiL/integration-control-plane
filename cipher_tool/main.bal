import ballerina/io;
import ballerina/crypto;
import ballerina/file;

const string DEFAULT_PUBLIC_KEY_PATH = "resources/public_key.pem";
const string DEFAULT_PRIVATE_KEY_PATH = "resources/private_key.pem";

// Key paths and passphrase are configurable.
// Override at runtime via the BAL_CONFIG_DATA environment variable (TOML format), e.g.:
//   BAL_CONFIG_DATA='privateKeyPassphrase="secret"' bal run -- ...
//   BAL_CONFIG_DATA='privateKeyPassphrase="secret" newPublicKeyPath="resources/new_key.pem"' bal run -- ...
configurable string publicKeyPath = DEFAULT_PUBLIC_KEY_PATH;
configurable string privateKeyPath = DEFAULT_PRIVATE_KEY_PATH;
configurable string privateKeyPassphrase = "";
configurable string newPublicKeyPath = "";

// Positional arguments:
//   args[0]   TOML file path
//   args[1]   mode: "encrypt" (default, may be omitted), "decrypt", or "rotate"
//   args[1..] or args[2..]   one or more dot-notation key names
//
// Examples:
//   bal run -- config.toml api_key database.password
//   BAL_CONFIG_DATA='privateKeyPassphrase="secret"' \
//     bal run -- config_encrypted.toml decrypt api_key database.password
//   BAL_CONFIG_DATA='privateKeyPassphrase="secret" newPublicKeyPath="resources/new.pem"' \
//     bal run -- config_encrypted.toml rotate api_key database.password

public function main(string... args) returns error? {
    if args.length() < 2 {
        printUsage();
        return;
    }

    string tomlFilePath = args[0];
    string mode;
    string[] keys;

    if args[1] == "decrypt" || args[1] == "rotate" || args[1] == "encrypt" {
        mode = args[1];
        keys = args.slice(2);
    } else {
        mode = "encrypt";
        keys = args.slice(1);
    }

    if keys.length() == 0 {
        io:println("Error: at least one key must be specified.");
        return;
    }

    if mode == "decrypt" {
        check runDecrypt(tomlFilePath, keys);
    } else if mode == "rotate" {
        if newPublicKeyPath == "" {
            io:println("Error: rotate requires newPublicKeyPath (set via BAL_CONFIG_DATA).");
            return;
        }
        check runRotate(tomlFilePath, keys);
    } else {
        check runEncrypt(tomlFilePath, keys);
    }
}

// Reads the source TOML, encrypts specified keys, writes *_encrypted.toml.
function runEncrypt(string tomlFilePath, string[] keys) returns error? {
    boolean result = check file:test("foo/bar.txt", file:EXISTS); // or file:READABLE
    map<json> tomlContent = check readTomlFile(tomlFilePath);
    crypto:PublicKey pubKey = check crypto:decodeRsaPublicKeyFromCertFile(publicKeyPath);

    map<json> encryptedContent = {};
    foreach string key in keys {
        json value = check getNestedValue(tomlContent, key);
        byte[] encrypted = check crypto:encryptRsaEcb(value.toString().toBytes(), pubKey, crypto:PKCS1);
        check setNestedValue(encryptedContent, key, encrypted.toBase64());
        io:println(string `Encrypted: ${key}`);
    }

    string outputPath = getOutputPath(tomlFilePath);
    check writeTomlFile(outputPath, encryptedContent);
    io:println(string `Written to: ${outputPath}`);
}

// Reads an encrypted TOML, decrypts specified keys, prints plaintext to stdout.
function runDecrypt(string tomlFilePath, string[] keys) returns error? {
    map<json> tomlContent = check readTomlFile(tomlFilePath);

    // Load key once for all values
    crypto:PrivateKey privKey = privateKeyPassphrase == ""
        ? check crypto:decodeRsaPrivateKeyFromKeyFile(privateKeyPath)
        : check crypto:decodeRsaPrivateKeyFromKeyFile(privateKeyPath, keyPassword = privateKeyPassphrase);

    io:println("Decrypted values:");
    foreach string key in keys {
        json encVal = check getNestedValue(tomlContent, key);
        string plaintext = check decryptWithKey(encVal.toString(), privKey);
        io:println(string `  ${key} = ${plaintext}`);
    }
}

// Decrypts specified keys with the current private key, re-encrypts with a new public key,
// writes *_rotated.toml. Example: config_encrypted.toml -> config_rotated.toml
function runRotate(string tomlFilePath, string[] keys) returns error? {
    map<json> tomlContent = check readTomlFile(tomlFilePath);

    // Load both keys once up front
    crypto:PrivateKey oldPrivKey = privateKeyPassphrase == ""
        ? check crypto:decodeRsaPrivateKeyFromKeyFile(privateKeyPath)
        : check crypto:decodeRsaPrivateKeyFromKeyFile(privateKeyPath, keyPassword = privateKeyPassphrase);
    crypto:PublicKey newPubKey = check crypto:decodeRsaPublicKeyFromCertFile(newPublicKeyPath);

    foreach string key in keys {
        json encVal = check getNestedValue(tomlContent, key);
        string plaintext = check decryptWithKey(encVal.toString(), oldPrivKey);
        byte[] reEncrypted = check crypto:encryptRsaEcb(plaintext.toBytes(), newPubKey, crypto:PKCS1);
        check setNestedValue(tomlContent, key, reEncrypted.toBase64());
        io:println(string `Rotated: ${key}`);
    }

    string outputPath = getRotatedOutputPath(tomlFilePath);
    check writeTomlFile(outputPath, tomlContent);
    io:println(string `Written to: ${outputPath}`);
}

function printUsage() {
    io:println("cipher_tool — encrypt sensitive values in TOML config files");
    io:println("");
    io:println("Usage:");
    io:println("  Encrypt  bal run -- <toml_file> [encrypt] <key1> [key2] ...");
    io:println("  Decrypt  BAL_CONFIG_DATA='privateKeyPassphrase=\"<pass>\"' \\");
    io:println("             bal run -- <toml_file> decrypt <key1> [key2] ...");
    io:println("  Rotate   BAL_CONFIG_DATA='privateKeyPassphrase=\"<pass>\" newPublicKeyPath=\"<path>\"' \\");
    io:println("             bal run -- <toml_file> rotate <key1> [key2] ...");
    io:println("");
    io:println("Configurable options (set via BAL_CONFIG_DATA in TOML format):");
    io:println("  publicKeyPath        default: " + DEFAULT_PUBLIC_KEY_PATH);
    io:println("  privateKeyPath       default: " + DEFAULT_PRIVATE_KEY_PATH);
    io:println("  privateKeyPassphrase default: (empty)");
    io:println("  newPublicKeyPath     required for rotate");
    io:println("");
    io:println("Keys support dot notation for nested values (e.g. database.password).");
}
