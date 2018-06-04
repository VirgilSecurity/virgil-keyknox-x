//
//  KeyknoxManager+Operations.swift
//  VirgilSDKKeyknox iOS
//
//  Created by Oleksandr Deundiak on 6/4/18.
//  Copyright © 2018 Virgil Security. All rights reserved.
//

import Foundation
import VirgilSDK
import VirgilCrypto
import VirgilCryptoApiImpl

extension KeyknoxManager {
    internal func makePullValueOperation() -> GenericOperation<EncryptedKeyknoxData> {
        return CallbackOperation { operation, completion in
            do {
                let token: AccessToken = try operation.findDependencyResult()
                
                let response = try self.keyknoxClient.pullValue(token: token.stringRepresentation())
                
                completion(response, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
    
    internal func makePushValueOperation() -> GenericOperation<EncryptedKeyknoxData> {
        return CallbackOperation { operation, completion in
            do {
                let token: AccessToken = try operation.findDependencyResult()
                let data: (Data, Data) = try operation.findDependencyResult()
                
                let response = try self.keyknoxClient.pushValue(meta: data.0, data: data.1, token: token.stringRepresentation())
                
                completion(response, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
    
    internal func makeDecryptOperation(publicKeys: [VirgilPublicKey],
                                       privateKey: VirgilPrivateKey) -> GenericOperation<DecryptedKeyknoxData> {
        return CallbackOperation { operation, completion in
            do {
                let keyknoxData: EncryptedKeyknoxData = try operation.findDependencyResult()
                
                let cipher = Cipher()
                try cipher.setContentInfo(keyknoxData.meta)
                let privateKeyData = self.crypto.exportPrivateKey(privateKey)
                let decryptedData = try cipher.decryptData(keyknoxData.data, recipientId: privateKey.identifier, privateKey: privateKeyData, keyPassword: nil)
                let meta = try cipher.contentInfo()
                
                let signedId = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignerId)
                let signature = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignature)
                
                let signer = Signer(hash: kHashNameSHA512)
                
                guard let publicKey = publicKeys.first(where: { $0.identifier == signedId }) else {
                    throw NSError() // FIXME
                }
                
                let publicKeyData = self.crypto.exportPublicKey(publicKey)
                
                do {
                    try signer.verifySignature(signature, data: decryptedData, publicKey: publicKeyData)
                }
                catch {
                    throw NSError() // FIXME
                }
                
                let result = DecryptedKeyknoxData(meta: meta, data: decryptedData, version: keyknoxData.version)
                
                completion(result, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
    
    internal func makeExtractDataOperation(data: Data? = nil) -> GenericOperation<Data> {
        return CallbackOperation { operation, completion in
            if let data = data {
                completion(data, nil)
                return
            }
            
            do {
                let data: DecryptedKeyknoxData = try operation.findDependencyResult()
                completion(data.data, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
    
    internal func makeEncryptOperation(publicKeys: [VirgilPublicKey],
                                       privateKey: VirgilPrivateKey) -> GenericOperation<(Data, Data)> {
        return CallbackOperation { operation, completion in
            do {
                let data: Data = try operation.findDependencyResult()
                
                let signer = Signer(hash: kHashNameSHA512)
                let privateKeyData = self.crypto.exportPrivateKey(privateKey)
                let signature = try signer.sign(data, privateKey: privateKeyData, keyPassword: nil)
                
                let cipher = Cipher()
                try cipher.setData(privateKey.identifier, forKey: VirgilCrypto.CustomParamKeySignerId)
                try cipher.setData(signature, forKey: VirgilCrypto.CustomParamKeySignature)
                try publicKeys
                    .map { return ($0.identifier, self.crypto.exportPublicKey($0)) }
                    .forEach { try cipher.addKeyRecipient($0, publicKey: $1) }
                let encryptedData = try cipher.encryptData(data, embedContentInfo: false)
                let meta = try cipher.contentInfo()
                
                completion((meta, encryptedData), nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
}
