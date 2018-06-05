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
    @objc public let crypto = VirgilCrypto()
    @objc public let keyknoxManager: KeyknoxManager
    @objc public let publicKeys: [VirgilPublicKey]
    @objc public let privateKey: VirgilPrivateKey
    @objc private(set) public var cache: Dictionary<String, VirgilPrivateKey> = [:]
    
    private let queue = DispatchQueue(label: "KeyknoxPrivateKeyStorageQueue")
    
    @objc public init(keyknoxManager: KeyknoxManager,
                      publicKeys: [VirgilPublicKey], privateKey: VirgilPrivateKey) {
        self.keyknoxManager = keyknoxManager
        self.publicKeys = publicKeys
        self.privateKey = privateKey

        super.init()
    }
        
    open func store(privateKey: VirgilPrivateKey, withName name: String) -> GenericOperation<Void> {
        return CallbackOperation { _, _ in
            
            
        }
    }
    
    open func loadPrivateKey(withName name: String) -> GenericOperation<VirgilPrivateKey> {
        return CallbackOperation { _, _ in
            
        }
    }
    
    //    - (BOOL)existsKeyEntryWithName:(NSString * __nonnull)name;
    //
    //    /**
    //     Removes VSSKeyEntry with given name
    //     @param name NSString with VSSKeyEntry name
    //     @param errorPtr NSError pointer to return error if needed
    //     @return YES if succeeded, NO otherwise
    //     */
    //    - (BOOL)deleteKeyEntryWithName:(NSString * __nonnull)name error:(NSError * __nullable * __nullable)errorPtr;
    //
    //    /**
    //     Configuration.
    //     See VSSKeyStorageConfiguration
    //     */
    //    @property (nonatomic, copy, readonly) VSSKeyStorageConfiguration * __nonnull configuration;
    //
    //    /**
    //     Initializer.
    //
    //     @param configuration Configuration
    //     @return initialized VSSKeyStorage instance
    //     */
    //    - (instancetype __nonnull)initWithConfiguration:(VSSKeyStorageConfiguration * __nonnull)configuration NS_DESIGNATED_INITIALIZER;
    //
    //    /**
    //     Updates key entry.
    //
    //     @param keyEntry New VSSKeyEntry instance
    //     @param errorPtr NSError pointer to return error if needed
    //     @return YES if storing succeeded, NO otherwise
    //     */
    //    - (BOOL)updateKeyEntry:(VSSKeyEntry * __nonnull)keyEntry error:(NSError * __nullable * __nullable)errorPtr;
    //
    //    /**
    //     Returns all keys in the storage.
    //
    //     @param errorPtr NSError pointer to return error if needed
    //     @return NSArray with all keys
    //     */
    //    - (NSArray<VSSKeyEntry *> * __nullable)getAllKeysWithError:(NSError * __nullable * __nullable)errorPtr;
    //
    //    /**
    //     Returns all keys tags in the storage.
    //
    //     @param errorPtr NSError pointer to return error if needed
    //     @return NSArray with all tags
    //     */
    //    - (NSArray<VSSKeyAttrs *> * __nullable)getAllKeysAttrsWithError:(NSError * __nullable * __nullable)errorPtr;
    //
    //    /**
    //     Stores multiple key entries.
    //
    //     @param keyEntries NSArray with VSSKeyEntry instances to store
    //     @param errorPtr NSError pointer to return error if needed
    //     @return YES if storing succeeded, NO otherwise
    //     */
    //    - (BOOL)storeKeyEntries:(NSArray<VSSKeyEntry *> * __nonnull)keyEntries error:(NSError * __nullable * __nullable)errorPtr;
    //
    //    /**
    //     Removes multiple key entries with given names.
    //
    //     @param names NSArray with names
    //     @param errorPtr NSError pointer to return error if needed
    //     @return YES if succeeded, NO otherwise
    //     */
    //    - (BOOL)deleteKeyEntriesWithNames:(NSArray<NSString *> * __nonnull)names error:(NSError * __nullable * __nullable)
    
    open func removeAllKeys() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.keyknoxManager.pushData(Data(), publicKeys: self.publicKeys, privateKey: self.privateKey).start() { result in
                switch result {
                case .success(_):
                    self.cache = [:]
                    completion((), nil)

                case .failure(let error):
                    completion(nil, error)
                }
            }
        }
    }
    
    open func sync() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.queue.sync {
                    let data = try self.keyknoxManager.pullData(publicKeys: self.publicKeys,
                                                            privateKey: self.privateKey)
                        .startSync().getResult()

                    self.cache = try self.parseData(data.data)
                }

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
    
    private func serializeDict(_ dict: Dictionary<String, VirgilPrivateKey>) throws -> Data {
        let exportDict = Dictionary(uniqueKeysWithValues: dict.map { return ($0.key , self.crypto.exportPrivateKey($0.value)) })
        
        return try JSONEncoder().encode(exportDict)
    }
    
    private func parseData(_ data: Data) throws -> Dictionary<String, VirgilPrivateKey> {
        let dict = try JSONDecoder().decode(Dictionary<String, Data>.self, from: data)
        
        return Dictionary(uniqueKeysWithValues: try dict.map { return ($0.key , try self.crypto.importPrivateKey(from: $0.value)) })
    }
}
