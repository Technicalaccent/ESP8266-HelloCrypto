#include <ESP8266WiFi.h>
#include <TypeConversion.h>
#include <Crypto.h>

namespace TypeCast = experimental::TypeConversion;

constexpr char masterKey[] PROGMEM = "w86vn@rpfA O+S"; // Use 8 random characters or more

void setup() {
  
  WiFi.persistent(false);

  Serial.begin(115200);

  Serial.println();
  Serial.println();
}

void loop() {
  // This serves only to demonstrate the library use. See the header file for a full list of functions.

  using namespace experimental::crypto;

  String exampleData = F("Hello Crypto World!");
  Serial.println(String(F("This is our example data: ")) + exampleData);

  uint8_t resultArray[SHA256::NATURAL_LENGTH] { 0 };
  uint8_t derivedKey[ENCRYPTION_KEY_LENGTH] { 0 };

  static uint32_t encryptionCounter = 0;


  // Generate the salt to use for HKDF
  uint8_t hkdfSalt[16] { 0 };
  getNonceGenerator()(hkdfSalt, sizeof hkdfSalt);

  // Generate the key to use for HMAC and encryption
  HKDF hkdfInstance(FPSTR(masterKey), (sizeof masterKey) - 1, hkdfSalt, sizeof hkdfSalt); // (sizeof masterKey) - 1 removes the terminating null value of the c-string
  hkdfInstance.produce(derivedKey, sizeof derivedKey);

  // Hash
  SHA256::hash(exampleData.c_str(), exampleData.length(), resultArray);
  Serial.println(String(F("\nThis is the SHA256 hash of our example data, in HEX format:\n")) + TypeCast::uint8ArrayToHexString(resultArray, sizeof resultArray));
  Serial.println(String(F("This is the SHA256 hash of our example data, in HEX format, using String output:\n")) + SHA256::hash(exampleData));


  // HMAC
  // Note that HMAC output length is limited
  SHA256::hmac(exampleData.c_str(), exampleData.length(), derivedKey, sizeof derivedKey, resultArray, sizeof resultArray);
  Serial.println(String(F("\nThis is the SHA256 HMAC of our example data, in HEX format:\n")) + TypeCast::uint8ArrayToHexString(resultArray, sizeof resultArray));
  Serial.println(String(F("This is the SHA256 HMAC of our example data, in HEX format, using String output:\n")) + SHA256::hmac(exampleData, derivedKey, sizeof derivedKey, SHA256::NATURAL_LENGTH));


  // Authenticated Encryption with Associated Data (AEAD)
  String dataToEncrypt = F("This data is not encrypted.");
  uint8_t resultingNonce[12] { 0 }; // The nonce is always 12 bytes
  uint8_t resultingTag[16] { 0 }; // The tag is always 16 bytes

  Serial.println(String(F("\nThis is the data to encrypt: ")) + dataToEncrypt);

  // Note that the key must be ENCRYPTION_KEY_LENGTH long.
  ChaCha20Poly1305::encrypt(dataToEncrypt.begin(), dataToEncrypt.length(), derivedKey, &encryptionCounter, sizeof encryptionCounter, resultingNonce, resultingTag);
  Serial.println(String(F("Encrypted data: ")) + dataToEncrypt);

  bool decryptionSucceeded = ChaCha20Poly1305::decrypt(dataToEncrypt.begin(), dataToEncrypt.length(), derivedKey, &encryptionCounter, sizeof encryptionCounter, resultingNonce, resultingTag);
  encryptionCounter++;

  if (decryptionSucceeded) {
    Serial.print(F("Decryption succeeded. Result: "));
  } else {
    Serial.print(F("Decryption failed. Result: "));
  }

  Serial.println(dataToEncrypt);


  Serial.println(F("\n##########################################################################################################\n"));

  delay(10000);
}
