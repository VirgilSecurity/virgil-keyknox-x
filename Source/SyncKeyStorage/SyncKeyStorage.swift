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

public protocol CloudKeyStorageProtocol {
    func storeEntries(_ keyEntries: [KeyEntry]) -> GenericOperation<Void>
    func storeEntry(data: Data, name: String, meta: [String: String]?) -> GenericOperation<Void>
    func updateEntry(data: Data, name: String, meta: [String: String]?) -> GenericOperation<Void>
    func retrieveAllEntries() -> [CloudEntry]
    func retrieveEntry(withName name: String) -> CloudEntry?
    func existsEntry(withName name: String) -> Bool
    func deleteEntry(withName name: String) -> GenericOperation<Void>
    func deleteEntries(withNames names: [String]) -> GenericOperation<Void>
    func deleteAllEntries() -> GenericOperation<Void>
    func retrieveCloudEntries() -> GenericOperation<Void>
}

extension CloudKeyStorage: CloudKeyStorageProtocol { }

public protocol KeychainStorageProtocol {
    func store(data: Data, withName name: String, meta: [String: String]?) throws -> KeychainEntry
    func updateEntry(withName name: String, data: Data, meta: [String: String]?) throws
    func retrieveEntry(withName name: String) throws -> KeychainEntry
    func retrieveAllEntries() throws -> [KeychainEntry]
    func deleteEntry(withName name: String) throws
}

extension KeychainStorage: KeychainStorageProtocol { }

@objc(VSKSyncKeyStorage) open class SyncKeyStorage: NSObject {
    @objc public static let keyknoxMetaKey = "keyknox"
    @objc public static let keyknoxMetaValue = "1"

    private let keychainStorage: KeychainStorageProtocol
    private let cloudKeyStorage: CloudKeyStorageProtocol

    private static let queue = DispatchQueue(label: "SyncKeyStorageQueue")

    internal init(keychainStorage: KeychainStorageProtocol, cloudKeyStorage: CloudKeyStorageProtocol) {
        self.keychainStorage = keychainStorage
        self.cloudKeyStorage = cloudKeyStorage

        super.init()
    }

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
                    // FIXME: Optimize to run concurrently
                    try self.cloudKeyStorage.retrieveCloudEntries().startSync().getResult()

                    let keychainEntries = try self.keychainStorage.retrieveAllEntries()
                        .compactMap { entry -> (KeychainEntry?) in
                            // FIXME
                            guard let meta = entry.meta,
                                meta[SyncKeyStorage.keyknoxMetaKey] == SyncKeyStorage.keyknoxMetaValue else {
                                    return nil
                            }

                            return entry
                        }

                    let keychainSet = Set<String>(keychainEntries.map { $0.name })
                    let cloudSet = Set<String>(self.cloudKeyStorage.retrieveAllEntries().map { $0.name })

                    let entriesToDelete = [String](keychainSet.subtracting(cloudSet))
                    let entriesToStore = [String](cloudSet.subtracting(keychainSet))
                    let entriesToCompare = [String](keychainSet.intersection(cloudSet))

                    try self.deleteEntries(entriesToDelete)
                    try self.storeEntries(entriesToStore)
                    try self.compareEntries(entriesToCompare, keychainEntries: keychainEntries)

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    private func deleteEntries(_ entriesToDelete: [String]) throws {
        try entriesToDelete.forEach {
            try self.keychainStorage.deleteEntry(withName: $0)
        }
    }

    private func storeEntries(_ entriesToStore: [String]) throws {
        try entriesToStore.forEach {
            guard let cloudEntry = self.cloudKeyStorage.retrieveEntry(withName: $0) else {
                throw NSError() // FIXME
            }

            let meta: [String: String]?
            if var cloudMeta = cloudEntry.meta {
                cloudMeta[SyncKeyStorage.keyknoxMetaKey] = SyncKeyStorage.keyknoxMetaValue
                meta = cloudMeta
            }
            else {
                meta = [SyncKeyStorage.keyknoxMetaKey: SyncKeyStorage.keyknoxMetaValue]
            }

            _ = try self.keychainStorage.store(data: cloudEntry.data, withName: cloudEntry.name, meta: meta)
        }
    }

    private func compareEntries(_ entriesToCompare: [String], keychainEntries: [KeychainEntry]) throws {
        // Determine newest version and either update keychain entry or upload newer version to cloud
        try entriesToCompare.forEach { name in
            guard let keychainEntry = keychainEntries.first(where: { $0.name == name }),
                let cloudEntry = self.cloudKeyStorage.retrieveEntry(withName: name) else {
                    throw NSError() // FIXME
            }

            if keychainEntry.modificationDate < cloudEntry.modificationDate {
                let meta: [String: String]?
                if var cloudMeta = cloudEntry.meta {
                    cloudMeta[SyncKeyStorage.keyknoxMetaKey] = SyncKeyStorage.keyknoxMetaValue
                    meta = cloudMeta
                }
                else {
                    meta = [SyncKeyStorage.keyknoxMetaKey: SyncKeyStorage.keyknoxMetaValue]
                }

                try self.keychainStorage.updateEntry(withName: cloudEntry.name, data: cloudEntry.data, meta: meta)
            }
        }
    }
}
