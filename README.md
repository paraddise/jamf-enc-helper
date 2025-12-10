# jamf-enc-helper

Helper tool for encryption/decryption/signing Jamf secrets/tokens based on the Key stored in the Database.

## How Jamf Encrypts Keys

### Basics

`DatabaseEncryptionKey` - The key that is stored in the database and is used to encrypt everything else.

`DatabaseEncryptionKeyService` - A service for interacting with `DatabaseEncryptionKey`. It can retrieve/save it from the database in encrypted form or initialize it.

That is, it will give us an encrypted key, and we must encrypt it ourselves.

During initialization, it encrypts the key itself and generates a Seed.

```java
public void initializeDatabaseEncryptionKey() {
    String decryptedEncryptionKey = this.getKeySeed();
    DatabaseEncryptionAlgorithm algorithm = DatabaseEncryptionAlgorithm.AES256;
    KeyStrategyPair keyAndStrategy = this.keyEncryptionKeyService.encryptDatabaseEncryptionKey(decryptedEncryptionKey, algorithm);
    String encryptedEncryptionKey = keyAndStrategy.getKey();
    KeyEncryptionKeyStrategy keyEncryptionKeyStrategy = keyAndStrategy.getKeyEncryptionKeyStrategy();
    DatabaseEncryptionKey databaseEncryptionKey = new DatabaseEncryptionKey();
    databaseEncryptionKey.setEncryptedEncryptionKey(encryptedEncryptionKey);
    databaseEncryptionKey.setKeyEncryptionKeyName(keyEncryptionKeyStrategy.getKeyEncryptionKeyName());
    databaseEncryptionKey.setKeyEncryptionKeyVersion(keyEncryptionKeyStrategy.getKeyEncryptionKeyVersion());
    databaseEncryptionKey.setEncryptionType(algorithm);
    this.repository.save(databaseEncryptionKey);
}

private String getKeySeed() {
    SecureRandom random = new SecureRandom();
    return (new BigInteger(255, random)).toString(32);
}
```

`KeyEncryptionKeyStrategy` - A method for encrypting the key, but in fact this class should return a passphrase that can be used to decrypt the value in the database.

`KeyEncryptionKeyStrategyFactory` - Factory for `KeyEncryptionKeyStrategy`.

`KeyEncryptionKeyService` - Service for encrypting and decrypting the key in the database. With it, you can extract the key.

In fact, it iterates through all `KeyEncryptionKeyStrategy` instances returned by `KeyEncryptionKeyStrategyFactory` and tries to decrypt with each one. If it succeeds and the result is a string matching the format `"^[a-v0-9]*$"`, it returns it.

Let's consider what strategies `KeyEncryptionKeyStrategyFactory` has:

1. `AWSParameterStoreService` - Stores the secret in AWS
2. `CloudService` - Presumably used in cloud Jamf Pro, retrieves the passphrase from the `jamf_cloud` table
3. `JVMKeyEncryptionKey` - Retrieves from system properties `System.getProperty("keyEncryptionKey")`
4. `LegacyKeyEncryptionKeyStrategy` - The main method, marked as `Deprecated`, in fact it's a hardcoded key.

It looks like this:

[Caution: Insecure!]

```java
public String getKeyEncryptionKeyValue() {
    String allCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-=_+[]{}|;':,.<>?";
    StringBuilder t = new StringBuilder();
    t.append(allCharacters.charAt(53));
    t.append(allCharacters.charAt(38));
    t.append(allCharacters.charAt(64));
    t.append(allCharacters.charAt(59));
    t.append(allCharacters.charAt(55));
    t.append(allCharacters.charAt(72));
    t.append(allCharacters.charAt(87));
    t.append(allCharacters.charAt(71));
    t.append(allCharacters.charAt(24));
    t.append(allCharacters.charAt(67));
    t.append(allCharacters.charAt(66));
    t.append(allCharacters.charAt(53));
    t.append(allCharacters.charAt(10));
    t.append(allCharacters.charAt(32));
    t.append(allCharacters.charAt(12));
    t.append(allCharacters.charAt(39));
    t.append(allCharacters.charAt(60));
    t.append(allCharacters.charAt(58));
    t.append(allCharacters.charAt(51));
    t.append(allCharacters.charAt(37));
    t.append(allCharacters.charAt(5));
    t.append(allCharacters.charAt(7));
    t.append(allCharacters.charAt(1));
    t.append(allCharacters.charAt(37));
    t.append(allCharacters.charAt(80));
    t.append(allCharacters.charAt(72));
    t.append(allCharacters.charAt(38));
    t.append(allCharacters.charAt(83));
    t.append(allCharacters.charAt(9));
    t.append(allCharacters.charAt(88));
    return t.toString();
}
```


Next, `KeyEncryptionKeyService` creates an `Encrypter` with each key, which will then try to decrypt.

`Encrypter` - A wrapper class that can perform encrypt and decrypt operations. It accepts a password and encryption settings.

- In fact, the only method used to decrypt the key is `PBEWITHSHA256AND256BITAES-CBC-BC`

  - **PBE** - Password Based Encryption
  - **SHA256** - Hash function that will be used to generate the key and IV
  - **256 BIT AES** - We will use AES with a 256-bit key
  - **CBC** - Block cipher mode
  - **BC** - We will use the Bouncy Castle API for crypto operations. This is a library for `Java` and `C#`

In fact, we will use `org.bouncycastle.crypto.generators.PKCS12ParametersGenerator` to generate the Key and IV from the password.

This is somewhat disappointing because I couldn't find an implementation anywhere except Bouncy Castle.

After all, most implementations use `PBKDF2`.

[RSA Laboratories PKCS 12 v1.0: Personal Information Exchange Syntax](https://www.foo.be/docs-free/opensst/ref/pkcs-12v1.pdf) - You can read more about `PKCS12ParametersGenerator` here. The information we need is on page 15, section B.3.

When generating the key, we can pass an ID. In our case:

- We pass 1 first to get the key for the block cipher
- We pass 2 to get the IV for the block cipher

After that, we decrypt the key in the database.

### EncryptionService

`EncryptionService` - Service for encrypting any strings or bytes.

After we get the `EncryptionKey`, we create an `Encrypter`, to which we pass the `EncryptionKey` as a passphrase, and then you know the rest.

It has the method we need: `getSecret`

```java
public byte[] getSecret(String salt) {
    try {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec spec = new SecretKeySpec(salt.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(spec);
        return mac.doFinal(this.decryptedEncryptionKey.getBytes(StandardCharsets.UTF_8));
    }
}
```

What this function does:

- Accepts a salt and uses it as the key for `HmacSHA256`
- Takes a checksum of the `EncryptionKey`

### JWT

Now let's see how Jamf signs JWT tokens.

It signs them using the `HS256` algorithm.

#### SAML Token

`SsoTokenService` for tokens with type `saml-token`.

```java
public class SsoTokenService {
    @Value("${samltoken.salt}")
    private String salt;
}
```

The default salt is located in the `samltoken.properties` file, which is in `api-impl-11.7.0-t1719858598.jar`

#### Jamf Token

Similarly, we sign tokens with type `jamf-token`.

The salt is located in the same `.jar` file in the `api.properties` file.

### Summary

The entire security of Jamf relies on the Seed that was generated during initialization, because:

- We know the default salt and it's unlikely anyone changed it (it's unlikely anyone knows about it)
- `LegacyKeyEncryptionKeyStrategy` is still used and essentially we know the passphrase.

This information is relevant for Jamf version `11.7.0`.

## Building

### Prerequisites

- Go 1.24.6 or later

### Build from source

```bash
# Using Make
make build

# Or directly with go
go build -o jamf-enc-helper cmd/main.go
```

The binary will be created as `jamf-enc-helper` in the current directory.

### Running tests

```bash
make test
# or
go test ./...
```

## Usage

The tool provides several commands for working with Jamf encryption keys and tokens.

### Retrieving the Encrypted Key from Jamf Database

Before you can decrypt the database encryption key, you need to retrieve it from the Jamf database. The encrypted key is stored in the `encryption_key` table.

**SQL Query:**

```sql
SELECT encryption_key FROM encryption_key WHERE id = 0;
```

The `encryption_key` column contains the base64-encoded encrypted key that you can use with the `decrypt-db-key` command.

### Commands

#### `decrypt-db-key`

Decrypt a database encryption key using PBKDF.

```bash
jamf-enc-helper decrypt-db-key --in <base64_encrypted_key> [OPTIONS]
```

**Options:**
- `-p, --phrase`: Passphrase for PBKDF (default: `2M#84->)y^%2kGmN97ZLfhbL|-M:j?`)
- `-s, --salt`: Salt for PBKDF, base64 encoded (default: `qXPIMlY14wM=`)
- `-i, --iterations`: Iterations for PBKDF (default: `19`)
- `--in`: Input ciphertext in base64 (required)

**Example:**
```bash
# First, retrieve the encrypted key from the database:
# SELECT encryption_key FROM encryption_key WHERE id = 0;

# Then decrypt it:
jamf-enc-helper decrypt-db-key --in "base64_encrypted_key_from_database"
```

#### `encrypt-db-key`

Encrypt a key for database storage.

```bash
jamf-enc-helper encrypt-db-key -k <encryption_key> [OPTIONS]
```

**Options:**
- `-p, --phrase`: Passphrase for PBKDF (default: `2M#84->)y^%2kGmN97ZLfhbL|-M:j?`)
- `-s, --salt`: Salt for PBKDF, base64 encoded (default: `qXPIMlY14wM=`)
- `-i, --iterations`: Iterations for PBKDF (default: `19`)
- `-k, --enc_key`: Encryption key to encrypt (required)

**Example:**
```bash
jamf-enc-helper encrypt-db-key -k "your_encryption_key_here"
```

#### `jwt-saml-token`

Generate JWT secret for SAML token.

```bash
jamf-enc-helper jwt-saml-token -k <encryption_key> [OPTIONS]
```

**Options:**
- `-k, --enc_key`: Encryption key (required)
- `-s, --salt`: Salt for JWT, base64 encoded (optional, default: SAML token salt)

**Example:**
```bash
jamf-enc-helper jwt-saml-token -k "your_encryption_key_here"
```

#### `jwt-api-token`

Generate JWT secret for API token.

```bash
jamf-enc-helper jwt-api-token -k <encryption_key> [OPTIONS]
```

**Options:**
- `-k, --enc_key`: Encryption key (required)
- `-s, --salt`: Salt for JWT, base64 encoded (optional, default: API token salt)

**Example:**
```bash
jamf-enc-helper jwt-api-token -k "your_encryption_key_here"
```

#### `get-secret`

Get a secret using custom salt.

```bash
jamf-enc-helper get-secret -k <encryption_key> -s <salt>
```

**Options:**
- `-k, --enc_key`: Encryption key (required)
- `-s, --salt`: Salt for HMAC, base64 encoded (required)

**Example:**
```bash
jamf-enc-helper get-secret -k "your_encryption_key_here" -s "base64_salt_here"
```

### Getting Help

To see all available commands and options:

```bash
jamf-enc-helper --help
```

To get help for a specific command:

```bash
jamf-enc-helper <command> --help
```

## Default Values

The tool uses the following default values (matching Jamf's legacy implementation):

- **Default Passphrase**: `2M#84->)y^%2kGmN97ZLfhbL|-M:j?`
- **Default Salt**: `qXPIMlY14wM=` (base64) or `[169, 115, 200, 50, 86, 53, 227, 3]` (bytes)
- **Default Iterations**: `19`
- **Default API Token Salt**: `rn337^!h#!75t+jp@n%3^^6=4)1xe0x)oaap+##zw&4-uf5zj+`
- **Default SAML Token Salt**: `58^ip+2f_+7xcy^hg*6rqel_cc!6m=#h3(ghd!vg2*e!+#$ih=`

## License

See [LICENSE](LICENSE) file for details.
