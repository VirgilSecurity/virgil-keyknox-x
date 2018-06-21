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

@objc(VSKSyncKeyStorageError) public enum SyncKeyStorageError: Int, Error {
    case keychainEntryNotFoundWhileUpdating
    case cloudEntryNotFoundWhileUpdating

    case keychainEntryNotFoundWhileDeleting
    case cloudEntryNotFoundWhileDeleting

    case keychainEntryNotFoundWhileComparing
    case cloudEntryNotFoundWhileComparing

    case keychainEntryAlreadyExistsWhileStoring
    case cloudEntryAlreadyExistsWhileStoring

    case cloudEntryNotFoundWhileSyncing

    case invalidModificationDateInKeychainEntry
    case invalidCreationDateInKeychainEntry
    case noMetaInKeychainEntry

    case invalidKeysInEntryMeta
}

@objc(VSKSyncKeyStorage) open class SyncKeyStorage: NSObject {
    @objc public let identity: String
    public let cloudKeyStorage: CloudKeyStorageProtocol
    public let keychainStorage: KeychainStorageProtocol
    private let keychainUtils: KeychainUtils

    private static let queue = DispatchQueue(label: "SyncKeyStorageQueue")

    internal init(identity: String, keychainStorage: KeychainStorageProtocol,
                  cloudKeyStorage: CloudKeyStorageProtocol) {
        self.identity = identity
        self.keychainStorage = KeychainStorageWrapper(identity: identity, keychainStorage: keychainStorage)
        self.cloudKeyStorage = cloudKeyStorage
        self.keychainUtils = KeychainUtils()

        super.init()
    }

    @objc public convenience init(identity: String, cloudKeyStorage: CloudKeyStorage) throws {
        let configuration = try KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: configuration)

        self.init(identity: identity, keychainStorage: keychainStorage, cloudKeyStorage: cloudKeyStorage)
    }
}

extension SyncKeyStorage {
    open func updateEntry(withName name: String, data: Data, meta: [String: String]?) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            SyncKeyStorage.queue.async {
                do {
                    guard try self.keychainStorage.existsEntry(withName: name) else {
                        throw SyncKeyStorageError.keychainEntryNotFoundWhileUpdating
                    }

                    guard self.cloudKeyStorage.existsEntry(withName: name) else {
                        throw SyncKeyStorageError.cloudEntryNotFoundWhileUpdating
                    }

                    let cloudEntry = try self.cloudKeyStorage.updateEntry(withName: name, data: data,
                                                                          meta: meta).startSync().getResult()
                    let meta = try self.keychainUtils.createMetaForKeychain(from: cloudEntry)
                    try self.keychainStorage.updateEntry(withName: name, data: data, meta: meta)

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    @objc open func retrieveEntry(withName name: String) throws -> KeychainEntry {
        return try self.keychainStorage.retrieveEntry(withName: name)
    }

    open func deleteEntry(withName name: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            SyncKeyStorage.queue.async {
                do {
                    guard try self.keychainStorage.existsEntry(withName: name) else {
                        throw SyncKeyStorageError.keychainEntryNotFoundWhileDeleting
                    }

                    guard self.cloudKeyStorage.existsEntry(withName: name) else {
                        throw SyncKeyStorageError.cloudEntryNotFoundWhileDeleting
                    }

                    _ = try self.cloudKeyStorage.deleteEntry(withName: name).startSync().getResult()
                    _ = try self.keychainStorage.deleteEntry(withName: name)

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    open func storeEntry(withName name: String, data: Data,
                         meta: [String: String]? = nil) -> GenericOperation<KeychainEntry> {
        return CallbackOperation { _, completion in
            SyncKeyStorage.queue.async {
                do {
                    guard !(try self.keychainStorage.existsEntry(withName: name)) else {
                        throw SyncKeyStorageError.keychainEntryAlreadyExistsWhileStoring
                    }

                    guard !self.cloudKeyStorage.existsEntry(withName: name) else {
                        throw SyncKeyStorageError.cloudEntryAlreadyExistsWhileStoring
                    }

                    let cloudEntry = try self.cloudKeyStorage.storeEntry(withName: name, data: data,
                                                                         meta: meta).startSync().getResult()
                    let meta = try self.keychainUtils.createMetaForKeychain(from: cloudEntry)
                    let keychainEntry = try self.keychainStorage.store(data: data, withName: name, meta: meta)

                    completion(keychainEntry, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    open func sync() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            SyncKeyStorage.queue.async {
                do {
                    // TODO: Optimize to run concurrently
                    try self.cloudKeyStorage.retrieveCloudEntries().startSync().getResult()

                    let keychainEntries = try self.keychainStorage.retrieveAllEntries()
                        .compactMap(self.keychainUtils.filterKeyknoxKeychainEntry)

                    let keychainSet = Set<String>(keychainEntries.map { $0.name })
                    let cloudSet = Set<String>(self.cloudKeyStorage.retrieveAllEntries().map { $0.name })

                    let entriesToDelete = [String](keychainSet.subtracting(cloudSet))
                    let entriesToStore = [String](cloudSet.subtracting(keychainSet))
                    let entriesToCompare = [String](keychainSet.intersection(cloudSet))

                    try self.syncDeleteEntries(entriesToDelete)
                    try self.syncStoreEntries(entriesToStore)
                    try self.syncCompareEntries(entriesToCompare, keychainEntries: keychainEntries)

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }
}

// MARK: Sync helpers
extension SyncKeyStorage {
    private func syncDeleteEntries(_ entriesToDelete: [String]) throws {
        try entriesToDelete.forEach {
            try self.keychainStorage.deleteEntry(withName: $0)
        }
    }

    private func syncStoreEntries(_ entriesToStore: [String]) throws {
        try entriesToStore.forEach {
            guard let cloudEntry = self.cloudKeyStorage.retrieveEntry(withName: $0) else {
                throw SyncKeyStorageError.cloudEntryNotFoundWhileSyncing
            }

            let meta = try self.keychainUtils.createMetaForKeychain(from: cloudEntry)

            _ = try self.keychainStorage.store(data: cloudEntry.data, withName: cloudEntry.name, meta: meta)
        }
    }

    private func syncCompareEntries(_ entriesToCompare: [String], keychainEntries: [KeychainEntry]) throws {
        // Determine newest version and either update keychain entry or upload newer version to cloud
        try entriesToCompare.forEach { name in
            guard let keychainEntry = keychainEntries.first(where: { $0.name == name }) else {
                throw SyncKeyStorageError.keychainEntryNotFoundWhileComparing
            }

            guard let cloudEntry = self.cloudKeyStorage.retrieveEntry(withName: name) else {
                throw SyncKeyStorageError.cloudEntryNotFoundWhileComparing
            }

            let keychainDate = try self.keychainUtils.extractModificationDate(fromKeychainEntry: keychainEntry)

            if keychainDate.modificationDate < cloudEntry.modificationDate {
                let meta = try self.keychainUtils.createMetaForKeychain(from: cloudEntry)

                try self.keychainStorage.updateEntry(withName: cloudEntry.name, data: cloudEntry.data, meta: meta)
            }
        }
    }
}
