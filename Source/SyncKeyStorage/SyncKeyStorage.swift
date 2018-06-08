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
import VirgilSDK

@objc(VSKSyncKeyStorage) open class SyncKeyStorage: NSObject {
    private let keychainStorage: KeychainStorage
    private let cloudKeyStorage: CloudKeyStorage

    private static let queue = DispatchQueue(label: "SyncKeyStorageQueue")

    @objc public init(cloudKeyStorage: CloudKeyStorage) throws {
        let configuration = try KeychainStorageParams.makeKeychainStorageParams()
        self.keychainStorage = KeychainStorage(storageParams: configuration)
        self.cloudKeyStorage = cloudKeyStorage

        super.init()
    }

    open func sync() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            SyncKeyStorage.queue.async {
                do {
                    try self.cloudKeyStorage.sync().startSync().getResult()

                    let keychainEntries = try self.keychainStorage.retrieveAllEntries()
                        .compactMap { entry -> (KeychainEntry?) in
                            // FIXME
                            guard let meta = entry.meta, meta["keyknox"] == "1" else {
                                return nil
                            }

                            return entry
                        }

                    let keychainSet = Set<String>(keychainEntries.map { $0.name })
                    let cloudSet = Set<String>(self.cloudKeyStorage.cache.keys)

                    let entriesToDelete = [String](keychainSet.subtracting(cloudSet))
                    let entriesToStore = [String](cloudSet.subtracting(keychainSet))
                    let entriesToCompare = [String](keychainSet.intersection(cloudSet))

                    try entriesToDelete.forEach {
                        try self.keychainStorage.deleteEntry(withName: $0)
                    }

                    try entriesToStore.forEach {
                        guard let cloudEntry = self.cloudKeyStorage.cache[$0] else {
                            throw NSError() // FIXME
                        }

                        // FIXME
//                        self.keychainStorage.store(data: cloudEntry.,
//                            withName: <#T##String#>, meta: <#T##[String : String]?#>)
                    }

                    // Determine newest version and either update keychain entry or upload newer version to cloud
                    try entriesToCompare.forEach { name in
                        guard let keychainEntry = keychainEntries.first(where: { $0.name == name }),
                            let cloudEntry = self.cloudKeyStorage.cache[name] else {
                                throw NSError() // FIXME
                        }

                        // FIXME
//                        if keychainEntry.modificationDate > cloudEntry.
                    }

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }
}
