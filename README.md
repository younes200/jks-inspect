# README

## Overview

This tool is designed to read an Java KeyStore (JKS) file and extract key information about each certificate it contains. It provides a convenient way to view the aliases, SHA-256 signatures, creation dates, and the certificates themselves in a readable format. This utility is particularly useful for developers who need to quickly export the contents of a KeyStore.

## Features

- **List Aliases**: Retrieves all the aliases stored in the KeyStore.
- **SHA-256 Signatures**: Computes and displays the SHA-256 signature for each certificate.
- **Certificate Dates**: Shows the creation (valid from) date of each certificate.
- **Certificate Display**: Outputs each certificate in PEM format.
- **Output Formatting**: Supports both plain text and JSON output formats.
- **Flexible Keystore Input**: Accepts the keystore file either as a file path or as a Base64-encoded string via stdin.

## Prerequisites

- Java JDK 11 or later must be installed on your system.
- Gradle (This project uses Gradle for building and running).

## Building the Application

1. **Clone the Repository** (if applicable):

   ```
   git clone https://github.com/younes200/jks-inspect
   cd jks-inspect
   ```

2. **Build the Project**:

   Run the following command in the root directory of the project:

   ```
   gradle build
   ```

   This command compiles the code and generates an executable JAR file in the `build/libs` directory.

## Running the Application

To run the application, use one of the following commands:

### Using a Keystore File

```
java -jar build/libs/jksinspect-all.jar --keystore [path-to-keystore] --storepass [keystore-password] [-j]
```

Replace `[path-to-keystore]` with the path to your keystore file and `[keystore-password]` with the password for your keystore. The `-j` argument is optional and, if provided, will output the results in JSON format.

### Using Base64-Encoded Keystore via Stdin

```
echo "base64_encoded_keystore_string" | java -jar build/libs/jksinspect-all.jar --storepass [keystore-password] [-j]
```

Replace `base64_encoded_keystore_string` with your Base64-encoded keystore string and `[keystore-password]` with the password for your keystore.

## Examples

### File-Based Keystore

```
java -jar build/libs/jksinspect-all.jar --keystore /path/to/keystore.jks --storepass changeit -j
```

This command will display the keystore contents in JSON format.

### Base64-Encoded Keystore

```
echo "base64_encoded_keystore_string" | java -jar build/libs/jksinspect-all.jar --storepass changeit -j
```

This command will read the keystore content from stdin and display the contents in JSON format.


### Generate new keystore for testing:

```
keytool -genkeypair -alias mytestkey -keyalg RSA -keysize 2048 -validity 365 -keystore mytestkeystore.jks -storepass mykeystorepassword -keypass mykeypassword -dname "CN=Test User, OU=Test Department, O=Test Company, L=Test City, ST=Test State, C=Test Country"
```
