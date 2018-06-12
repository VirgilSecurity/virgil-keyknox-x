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
    func storeEntries(_ keyEntries: [KeyEntry]) -> GenericOperation<[CloudEntry]>
    func storeEntry(withName name: String, data: Data, meta: [String: String]?) -> GenericOperation<CloudEntry>
    func updateEntry(withName: String, data: Data, meta: [String: String]?) -> GenericOperation<CloudEntry>
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
    func existsEntry(withName name: String) throws -> Bool
}

extension KeychainStorage: KeychainStorageProtocol { }

@objc(VSKSyncKeyStorage) open class SyncKeyStorage: NSObject {
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
}

extension SyncKeyStorage {
    open func updateEntry(withName name: String, data: Data, meta: [String: String]?) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            SyncKeyStorage.queue.async {
                do {
                    guard try self.keychainStorage.existsEntry(withName: name),
                        self.cloudKeyStorage.existsEntry(withName: name) else {
                            // FIXME
                            throw NSError()
                    }

                    let cloudEntry = try self.cloudKeyStorage.updateEntry(withName: name, data: data,
                                                                          meta: meta).startSync().getResult()
                    let meta = try SyncKeyStorage.createMetaForKeychain(from: cloudEntry)
                    try self.keychainStorage.updateEntry(withName: name, data: data, meta: meta)

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    open func retrieveEntry(withName name: String) throws -> KeychainEntry {
        return try self.keychainStorage.retrieveEntry(withName: name)
    }

    open func deleteEntry(withName name: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            SyncKeyStorage.queue.async {
                do {
                    guard try self.keychainStorage.existsEntry(withName: name),
                        self.cloudKeyStorage.existsEntry(withName: name) else {
                            // FIXME
                            throw NSError()
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
                    guard !(try self.keychainStorage.existsEntry(withName: name)),
                        !self.cloudKeyStorage.existsEntry(withName: name) else {
                            // FIXME
                            throw NSError()
                    }

                    let cloudEntry = try self.cloudKeyStorage.storeEntry(withName: name, data: data,
                                                                         meta: meta).startSync().getResult()
                    let meta = try SyncKeyStorage.createMetaForKeychain(from: cloudEntry)
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
                    // FIXME: Optimize to run concurrently
                    try self.cloudKeyStorage.retrieveCloudEntries().startSync().getResult()

                    let keychainEntries = try self.keychainStorage.retrieveAllEntries()
                        .compactMap(SyncKeyStorage.filterKeyknoxKeychainEntry)

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
                throw NSError() // FIXME
            }

            let meta = try SyncKeyStorage.createMetaForKeychain(from: cloudEntry)

            _ = try self.keychainStorage.store(data: cloudEntry.data, withName: cloudEntry.name, meta: meta)
        }
    }

    private func syncCompareEntries(_ entriesToCompare: [String], keychainEntries: [KeychainEntry]) throws {
        // Determine newest version and either update keychain entry or upload newer version to cloud
        try entriesToCompare.forEach { name in
            guard let keychainEntry = keychainEntries.first(where: { $0.name == name }),
                let cloudEntry = self.cloudKeyStorage.retrieveEntry(withName: name) else {
                    throw NSError() // FIXME
            }

            let keychainModificationDate = try SyncKeyStorage.extractModificationDate(fromKeychainEntry: keychainEntry)

            if keychainModificationDate < cloudEntry.modificationDate {
                let meta = try SyncKeyStorage.createMetaForKeychain(from: cloudEntry)

                try self.keychainStorage.updateEntry(withName: cloudEntry.name, data: cloudEntry.data, meta: meta)
            }
        }
    }
}

// MARK: Keychain format helper
extension SyncKeyStorage {
    @objc public static let keyknoxMetaCreationDateKey = "k_cda"
    @objc public static let keyknoxMetaModificationDateKey = "k_mda"

    private static func extractModificationDate(fromKeychainEntry keychainEntry: KeychainEntry) throws -> Date {
        guard let meta = keychainEntry.meta,
            let modificationTimestampStr = meta[self.keyknoxMetaModificationDateKey],
            let modificationTimestamp = Int(modificationTimestampStr) else {
                throw NSError()
        }

        return Date(timeIntervalSince1970: TimeInterval(modificationTimestamp))
    }

    private static func filterKeyknoxKeychainEntry(_ keychainEntry: KeychainEntry) -> KeychainEntry? {
        // FIXME
        guard let meta = keychainEntry.meta,
            meta[self.keyknoxMetaCreationDateKey] != nil,
            meta[self.keyknoxMetaModificationDateKey] != nil else {
                return nil
        }

        return keychainEntry
    }

    private static func createMetaForKeychain(from cloudEntry: CloudEntry) throws -> [String: String] {
        var additionalDict = [
            self.keyknoxMetaCreationDateKey: "\(Int(cloudEntry.creationDate.timeIntervalSince1970))",
            self.keyknoxMetaModificationDateKey: "\(Int(cloudEntry.modificationDate.timeIntervalSince1970))"
        ]

        if let meta = cloudEntry.meta {
            try additionalDict.merge(meta, uniquingKeysWith: { _, _ in throw NSError() /* FIXME */ })
        }

        return additionalDict
    }
}
