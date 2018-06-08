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
@testable import VirgilSDKKeyknox
import XCTest
import VirgilSDK
import VirgilCryptoApiImpl

class VSK004_SyncKeyStorageTests: XCTestCase {
    func test001() {
        let config = TestConfig.readFromBundle()
        let crypto = VirgilCrypto()
        let apiKey = try! crypto.importPrivateKey(from: Data(base64Encoded: config.ApiPrivateKey)!)
        
        let generator = JwtGenerator(apiKey: apiKey, apiPublicKeyIdentifier: config.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(), appId: config.AppId, ttl: 100)
        let provider = GeneratorJwtProvider(jwtGenerator: generator, defaultIdentity: "test")
        let client = KeyknoxClient(serviceUrl: URL(string: config.ServiceURL)!)
        
        let keyknoxManager = KeyknoxManager(accessTokenProvider: provider, keyknoxClient: client)
        
        let keyPair = try! crypto.generateKeyPair()
        
        let cloudKeyStorage = CloudKeyStorage(keyknoxManager: keyknoxManager, publicKeys: [keyPair.publicKey], privateKey: keyPair.privateKey)
        
        let syncKeyStorage = try! SyncKeyStorage(cloudKeyStorage: cloudKeyStorage)
        
        let params = try! KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: params)
        
        try! keychainStorage.deleteAllEntries()
        
        let _ = try! syncKeyStorage.sync().startSync().getResult()
        XCTAssert(try! keychainStorage.retrieveAllEntries().count == 0)
        
        let data = NSUUID().uuidString.data(using: .utf8)!
        let name = NSUUID().uuidString
        
        let keyEntry = KeyEntry(name: name, data: data)
        
        let _ = try! cloudKeyStorage.storeEntries([keyEntry]).startSync().getResult()
        let keychainEntries = try! keychainStorage.retrieveAllEntries()
        XCTAssert(keychainEntries.count == 1)
        let keychainEntry = keychainEntries[0]

        // FIXME
//        keychainEntry.creationDate, modificationDate
        
        XCTAssert(keychainEntry.name == name)
        XCTAssert(keychainEntry.data == data)
    }
}
