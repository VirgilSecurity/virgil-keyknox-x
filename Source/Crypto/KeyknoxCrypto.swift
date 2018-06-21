//
// Copyright (C) 2015-2018 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation
import VirgilCryptoAPI
import VirgilCryptoApiImpl
import VirgilCrypto

open class KeyknoxCrypto {
    public let crypto: VirgilCrypto

    public init(crypto: VirgilCrypto = VirgilCrypto()) {
        self.crypto = crypto
    }
}

extension KeyknoxCrypto: KeyknoxCryptoProtocol {
    open func decrypt(encryptedKeyknoxValue: EncryptedKeyknoxValue, privateKey: PrivateKey,
                      publicKeys: [PublicKey]) throws -> DecryptedKeyknoxValue {
        guard let virgilPrivateKey = privateKey as? VirgilPrivateKey,
            let virgilPublicKeys = publicKeys as? [VirgilPublicKey] else {
                throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        let cipher = Cipher()
        try cipher.setContentInfo(encryptedKeyknoxValue.meta)
        let privateKeyData = self.crypto.exportPrivateKey(virgilPrivateKey)
        let decryptedData: Data
        do {
            decryptedData = try cipher.decryptData(encryptedKeyknoxValue.value,
                                                   recipientId: virgilPrivateKey.identifier,
                                                   privateKey: privateKeyData, keyPassword: nil)
        }
        catch {
            throw KeyknoxManagerError.decryptionFailed
        }

        let meta = try cipher.contentInfo()

        let signedId = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignerId)
        let signature = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignature)

        let signer = Signer(hash: kHashNameSHA512)

        guard let publicKey = virgilPublicKeys.first(where: { $0.identifier == signedId }) else {
            throw KeyknoxManagerError.signerNotFound
        }

        let publicKeyData = self.crypto.exportPublicKey(publicKey)

        do {
            try signer.verifySignature(signature, data: decryptedData, publicKey: publicKeyData)
        }
        catch {
            throw KeyknoxManagerError.signatureVerificationFailed
        }

        return DecryptedKeyknoxValue(meta: meta, value: decryptedData,
                                     version: encryptedKeyknoxValue.version,
                                     keyknoxHash: encryptedKeyknoxValue.keyknoxHash)
    }

    open func encrypt(data: Data, privateKey: PrivateKey, publicKeys: [PublicKey]) throws -> (Data, Data) {
        guard let virgilPrivateKey = privateKey as? VirgilPrivateKey,
            let virgilPublicKeys = publicKeys as? [VirgilPublicKey] else {
                throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        let signer = Signer(hash: kHashNameSHA512)
        let privateKeyData = self.crypto.exportPrivateKey(virgilPrivateKey)
        let signature = try signer.sign(data, privateKey: privateKeyData, keyPassword: nil)

        let cipher = Cipher()
        try cipher.setData(virgilPrivateKey.identifier, forKey: VirgilCrypto.CustomParamKeySignerId)
        try cipher.setData(signature, forKey: VirgilCrypto.CustomParamKeySignature)
        try virgilPublicKeys
            .map { return ($0.identifier, self.crypto.exportPublicKey($0)) }
            .forEach { try cipher.addKeyRecipient($0, publicKey: $1) }
        let encryptedData = try cipher.encryptData(data, embedContentInfo: false)
        let meta = try cipher.contentInfo()

        return (meta, encryptedData)
    }
}
