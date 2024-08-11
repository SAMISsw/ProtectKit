import Foundation
import Security
import CommonCrypto

public class ProtectKit {

    public static func generateRSAKeyPair(tag: String, keySize: Int = 2048) -> (privateKey: SecKey?, publicKey: SecKey?) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag
            ]
        ]

        var privateKey: SecKey?
        var publicKey: SecKey?

        let status = SecKeyGeneratePair(attributes as CFDictionary, &publicKey, &privateKey)
        if status == errSecSuccess {
            return (privateKey, publicKey)
        } else {
            fatalError("Error generating RSA key pair: \(status)")
        }
    }

    public static func storeKey(key: SecKey, tag: String) -> Bool {
        let keyData = SecKeyCopyExternalRepresentation(key, nil) as Data?
        guard let keyData = keyData else { return false }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecValueData as String: keyData
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    public static func retrieveKey(tag: String) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var itemRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &itemRef)
        if status == errSecSuccess, let key = itemRef as? SecKey {
            return key
        } else {
            return nil
        }
    }

    public static func deleteKey(tag: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }

    public static func encrypt(data: Data, publicKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA256, data as CFData, &error) else {
            print("Encryption error: \(String(describing: error?.takeRetainedValue()))")
            return nil
        }
        return cipherText as Data
    }

    public static func decrypt(data: Data, privateKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let plainText = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA256, data as CFData, &error) else {
            print("Decryption error: \(String(describing: error?.takeRetainedValue()))")
            return nil
        }
        return plainText as Data
    }

    public static func exportPublicKeyToPEM(publicKey: SecKey) -> String? {
        guard let keyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else { return nil }
        let base64String = keyData.base64EncodedString()
        return "-----BEGIN PUBLIC KEY-----\n\(base64String)\n-----END PUBLIC KEY-----"
    }

    public static func exportPrivateKeyToPEM(privateKey: SecKey) -> String? {
        guard let keyData = SecKeyCopyExternalRepresentation(privateKey, nil) as Data? else { return nil }
        let base64String = keyData.base64EncodedString()
        return "-----BEGIN PRIVATE KEY-----\n\(base64String)\n-----END PRIVATE KEY-----"
    }

    public static func importPublicKeyFromPEM(pem: String) -> SecKey? {
        let base64String = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let keyData = Data(base64Encoded: base64String) else { return nil }
        
        let keyDict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error)
    }

    public static func importPrivateKeyFromPEM(pem: String) -> SecKey? {
        let base64String = pem
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let keyData = Data(base64Encoded: base64String) else { return nil }

        let keyDict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error)
    }

    public static func generateHash(data: Data, algorithm: HashAlgorithm) -> Data {
        var digest = Data(count: algorithm.length)
        _ = digest.withUnsafeMutableBytes { digestBytes in
            _ = data.withUnsafeBytes { dataBytes in
                algorithm.hashFunction(dataBytes.baseAddress, data.count, digestBytes.baseAddress)
            }
        }
        return digest
    }

    public enum HashAlgorithm {
        case sha256

        var length: Int {
            switch self {
            case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
            }
        }

        var hashFunction: (UnsafeRawPointer?, Int, UnsafeMutableRawPointer?) -> Void {
            switch self {
            case .sha256: return CC_SHA256
            }
        }
    }

    public static func generateToken(length: Int) -> String {
        var token = ""
        for _ in 0..<length {
            let randomByte = UInt8.random(in: 0...255)
            token.append(String(format: "%02x", randomByte))
        }
        return token
    }

    public static func generatePasswordHash(password: String) -> Data {
        let salt = Data("random_salt".utf8)
        let hash = SHA256.hash(data: password.data(using: .utf8)!)
        return salt + hash
    }

    public static func comparePasswordHash(password: String, hash: Data) -> Bool {
        let salt = hash.prefix(16)
        let storedHash = hash.suffix(32)
        let hashToCompare = SHA256.hash(data: password.data(using: .utf8)!)
        return storedHash == hashToCompare
    }

    public static func generateOTP(secret: String) -> String {
        let time = Date().timeIntervalSince1970
        let counter = Int(time / 30.0)
        let secretData = Data(secret.utf8)
        let hmac = HMAC<SHA1>.authenticationCode(for: Data("\(counter)".utf8), using: SymmetricKey(data: secretData))
        let otp = hmac.prefix(6).map { String(format: "%02x", $0) }.joined()
        return otp
    }

    public static func validateOTP(otp: String, secret: String) -> Bool {
        return generateOTP(secret: secret) == otp
    }

    public static func createSecureToken(length: Int) -> String {
        var token = ""
        for _ in 0..<length {
            let randomByte = UInt8.random(in: 0...255)
            token.append(String(format: "%02x", randomByte))
        }
        return token
    }

    public static func hashFileContents(filePath: String) -> Data? {
        guard let fileData = FileManager.default.contents(atPath: filePath) else { return nil }
        return SHA256.hash(data: fileData).data
    }

    public static func secureKeyStorage(tag: String, key: Data) -> Bool {
        let keychainItem: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecValueData as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        SecItemDelete(keychainItem as CFDictionary)
        let status = SecItemAdd(keychainItem as CFDictionary, nil)
        return status == errSecSuccess
    }

    public static func retrieveSecureKey(tag: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var dataTypeRef: AnyObject? = nil
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        if status == errSecSuccess {
            return dataTypeRef as? Data
        }
        return nil
    }

    public static func restoreKeyFromiCloud(tag: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny
        ]
        var itemRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &itemRef)
        if status == errSecSuccess {
            return itemRef as? Data
        }
        return nil
    }
}
