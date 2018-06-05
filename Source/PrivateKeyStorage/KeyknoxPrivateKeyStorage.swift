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
import VirgilCryptoApiImpl
import VirgilSDK

@objc(VSKKeyknoxPrivateKeyStorage) open class KeyknoxPrivateKeyStorage: NSObject {
    @objc public let crypto: VirgilCrypto
    @objc public let keyknoxManager: KeyknoxManager
    @objc public let publicKeys: [VirgilPublicKey]
    @objc public let privateKey: VirgilPrivateKey
    @objc private(set) public var cache: Dictionary<String, VirgilPrivateKey> = [:]
    
    private let queue = DispatchQueue(label: "KeyknoxPrivateKeyStorageQueue")
    
    @objc public init(keyknoxManager: KeyknoxManager,
                      publicKeys: [VirgilPublicKey], privateKey: VirgilPrivateKey,
                      crypto: VirgilCrypto = VirgilCrypto()) {
        self.keyknoxManager = keyknoxManager
        self.publicKeys = publicKeys
        self.privateKey = privateKey
        self.crypto = crypto

        super.init()
    }
}

extension KeyknoxPrivateKeyStorage {
    open func store(keyEntries: [(key: VirgilPrivateKey, name: String)]) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                for entry in keyEntries {
                    guard self.cache[entry.name] == nil else {
                        completion(nil, NSError()) // FIXME
                        return
                    }
                }
                
                for entry in keyEntries {
                    self.cache[entry.name] = entry.key
                }
                
                do {
                    let data = try self.serializeDict(self.cache)
                
                    let response = try self.keyknoxManager.pushData(data, publicKeys: self.publicKeys, privateKey: self.privateKey).startSync().getResult()
                
                    self.cache = try self.parseData(response.data)
                    
                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }
    
    open func store(privateKey: VirgilPrivateKey, withName name: String) -> GenericOperation<Void> {
        return self.store(keyEntries: [(privateKey, name)])
    }
    
    @objc open func loadKey(withName name: String) -> VirgilPrivateKey? {
        return self.cache[name]
    }
    
    @objc open func existsKey(withName name: String) -> Bool {
        return self.cache[name] != nil
    }
    
    open func deleteKey(withName name: String) -> GenericOperation<Void> {
        return self.deleteKeys(withNames: [name])
    }
    
    open func deleteKeys(withNames names: [String]) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                for name in names {
                    guard self.cache[name] != nil else {
                        completion(nil, NSError()) // FIXME
                        return
                    }
                }
                
                do {
                    for name in names {
                        self.cache.removeValue(forKey: name)
                    }
                
                    let data = try self.serializeDict(self.cache)
                
                    let response = try self.keyknoxManager.pushData(data, publicKeys: self.publicKeys, privateKey: self.privateKey).startSync().getResult()
                
                    self.cache = try self.parseData(response.data)
                
                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }
    
    open func deleteAllKeys() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    self.cache = [:]
                    
                    let data = try self.serializeDict(self.cache)
                    
                    let response = try self.keyknoxManager.pushData(data, publicKeys: self.publicKeys, privateKey: self.privateKey).startSync().getResult()
                    
                    self.cache = try self.parseData(response.data)
                    
                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }
    
    open func sync() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let data = try self.keyknoxManager.pullData(publicKeys: self.publicKeys,
                                                                privateKey: self.privateKey)
                        .startSync().getResult()
                
                    self.cache = try self.parseData(data.data)
                    
                    completion((), nil)
                }
                catch KeyknoxManagerError.keyknoxIsEmpty {
                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
        }
        }
    }
    
    private func serializeDict(_ dict: Dictionary<String, VirgilPrivateKey>) throws -> Data {
        let exportDict = Dictionary(uniqueKeysWithValues: dict.map { return ($0.key , self.crypto.exportPrivateKey($0.value)) })
        
        return try JSONEncoder().encode(exportDict)
    }
    
    private func parseData(_ data: Data) throws -> Dictionary<String, VirgilPrivateKey> {
        let dict = try JSONDecoder().decode(Dictionary<String, Data>.self, from: data)
        
        return Dictionary(uniqueKeysWithValues: try dict.map { return ($0.key , try self.crypto.importPrivateKey(from: $0.value)) })
    }
}
