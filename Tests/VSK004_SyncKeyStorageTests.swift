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
    private var syncKeyStorage: SyncKeyStorage!
    private var keychainStorage: KeychainStorage!
    private var cloudKeyStorage: CloudKeyStorage!
    
    override func setUp() {
        super.setUp()
        
        let config = TestConfig.readFromBundle()
        let crypto = VirgilCrypto()
        let apiKey = try! crypto.importPrivateKey(from: Data(base64Encoded: config.ApiPrivateKey)!)
        
        let generator = JwtGenerator(apiKey: apiKey, apiPublicKeyIdentifier: config.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(), appId: config.AppId, ttl: 100)
        let identity = NSUUID().uuidString
        let provider = GeneratorJwtProvider(jwtGenerator: generator, defaultIdentity: identity)
        let client = KeyknoxClient(serviceUrl: URL(string: config.ServiceURL)!)
        
        let keyknoxManager = KeyknoxManager(accessTokenProvider: provider, keyknoxClient: client)
        
        let keyPair = try! crypto.generateKeyPair()
        
        self.cloudKeyStorage = CloudKeyStorage(keyknoxManager: keyknoxManager, publicKeys: [keyPair.publicKey], privateKey: keyPair.privateKey)
        
        self.syncKeyStorage = try! SyncKeyStorage(cloudKeyStorage: self.cloudKeyStorage)

        let params = try! KeychainStorageParams.makeKeychainStorageParams()
        self.keychainStorage = KeychainStorage(storageParams: params)
        
        try! self.keychainStorage.deleteAllEntries()
    }
    
    func test001_syncStorage() {
        let _ = try! self.syncKeyStorage.sync().startSync().getResult()
        XCTAssert(try! self.keychainStorage.retrieveAllEntries().count == 0)

        var keyEntries = [VirgilSDKKeyknox.KeyEntry]()
        
        for _ in 0..<3 {
            let data = NSUUID().uuidString.data(using: .utf8)!
            let name = NSUUID().uuidString
            
            let keyEntry = KeyEntry(name: name, data: data)
            
            keyEntries.append(keyEntry)
        }

        let _ = try! self.cloudKeyStorage.storeEntries([keyEntries[0]]).startSync().getResult()
        let _ = try! self.syncKeyStorage.sync().startSync().getResult()
        let keychainEntries = try! self.keychainStorage.retrieveAllEntries()
        XCTAssert(keychainEntries.count == 1)
        XCTAssert(keychainEntries[0].name == keyEntries[0].name)
        XCTAssert(keychainEntries[0].data == keyEntries[0].data)

        // FIXME
        //        keychainEntry.creationDate  modificationDate

        let _ = try! self.syncKeyStorage.sync().startSync().getResult()
        let keychainEntries2 = try! self.keychainStorage.retrieveAllEntries()
        XCTAssert(keychainEntries2.count == 1)
        XCTAssert(keychainEntries2[0].name == keyEntries[0].name)
        XCTAssert(keychainEntries2[0].data == keyEntries[0].data)
        
        let _ = try! self.cloudKeyStorage.storeEntries([keyEntries[1]]).startSync().getResult()
        let _ = try! self.syncKeyStorage.sync().startSync().getResult()
        let keychainEntries3 = try! self.keychainStorage.retrieveAllEntries()
        XCTAssert(keychainEntries3.count == 2)
        XCTAssert(keychainEntries3[1].name == keyEntries[1].name)
        XCTAssert(keychainEntries3[1].data == keyEntries[1].data)
        
        try! self.keychainStorage.deleteAllEntries()
        let _ = try! self.syncKeyStorage.sync().startSync().getResult()
        let keychainEntries4 = try! self.keychainStorage.retrieveAllEntries()
        XCTAssert(keychainEntries4.count == 2)
        XCTAssert(keychainEntries4[0].name == keyEntries[0].name)
        XCTAssert(keychainEntries4[0].data == keyEntries[0].data)
        XCTAssert(keychainEntries4[1].name == keyEntries[1].name)
        XCTAssert(keychainEntries4[1].data == keyEntries[1].data)

        let _ = try! self.cloudKeyStorage.deleteEntry(withName: keyEntries[0].name).startSync().getResult()
        let _ = try! self.syncKeyStorage.sync().startSync().getResult()
        let keychainEntries5 = try! self.keychainStorage.retrieveAllEntries()
        XCTAssert(keychainEntries5.count == 1)
        XCTAssert(keychainEntries5[0].name == keyEntries[1].name)
        XCTAssert(keychainEntries5[0].data == keyEntries[1].data)
        
        let _ = try! self.cloudKeyStorage.deleteAllEntries().startSync().getResult()
        let _ = try! self.syncKeyStorage.sync().startSync().getResult()
        XCTAssert(try! self.keychainStorage.retrieveAllEntries().count == 0)
    }
}
