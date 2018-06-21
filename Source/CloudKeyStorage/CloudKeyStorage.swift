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
import VirgilSDK

@objc(VSKCloudKeyStorageError) public enum CloudKeyStorageError: Int, Error {
    case entryNotFound
    case entrySavingError
    case entryAlreadyExists
}

@objc(VSKCloudKeyStorage) open class CloudKeyStorage: NSObject {
    @objc public let keyknoxManager: KeyknoxManager
    private var cache: [String: CloudEntry] = [:]
    private var decryptedKeyknoxData: DecryptedKeyknoxValue?
    private let cloudEntrySerializer = CloudEntrySerializer()

    private let queue = DispatchQueue(label: "CloudKeyStorageQueue")

    @objc public init(keyknoxManager: KeyknoxManager) {
        self.keyknoxManager = keyknoxManager

        super.init()
    }
}

extension CloudKeyStorage: CloudKeyStorageProtocol {
    private func storeEntriesSync(_ keyEntries: [KeyEntry]) throws -> [CloudEntry] {
        for entry in keyEntries {
            guard self.cache[entry.name] == nil else {
                throw CloudKeyStorageError.entryAlreadyExists
            }
        }

        var cloudEntries = [CloudEntry]()
        for entry in keyEntries {
            let now = Date()
            let cloudEntry = CloudEntry(name: entry.name, data: entry.data,
                                        creationDate: now, modificationDate: now, meta: entry.meta)

            cloudEntries.append(cloudEntry)
            self.cache[entry.name] = cloudEntry
        }

        let data = try self.cloudEntrySerializer.serialize(dict: self.cache)

        let response = try self.keyknoxManager.pushValue(data, previousHash: self.decryptedKeyknoxData?.keyknoxHash)
            .startSync().getResult()

        self.cache = try self.cloudEntrySerializer.parse(data: response.value)
        self.decryptedKeyknoxData = response

        return cloudEntries
    }

    open func storeEntries(_ keyEntries: [KeyEntry]) -> GenericOperation<[CloudEntry]> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    completion(try self.storeEntriesSync(keyEntries), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    open func storeEntry(withName name: String, data: Data,
                         meta: [String: String]? = nil) -> GenericOperation<CloudEntry> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let cloudEntries = try self.storeEntriesSync([KeyEntry(name: name, data: data, meta: meta)])
                    guard cloudEntries.count == 1, let cloudEntry = cloudEntries.first else {
                        throw CloudKeyStorageError.entrySavingError
                    }

                    completion(cloudEntry, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    open func updateEntry(withName name: String, data: Data,
                          meta: [String: String]? = nil) -> GenericOperation<CloudEntry> {
        return CallbackOperation { _, completion in
            self.queue.async {
                let now = Date()
                let creationDate = self.cache[name]?.creationDate ?? now

                let cloudEntry = CloudEntry(name: name, data: data,
                                            creationDate: creationDate, modificationDate: now, meta: meta)

                self.cache[name] = cloudEntry

                do {
                    let data = try self.cloudEntrySerializer.serialize(dict: self.cache)

                    let response = try self.keyknoxManager
                        .pushValue(data, previousHash: self.decryptedKeyknoxData?.keyknoxHash)
                        .startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.parse(data: response.value)
                    self.decryptedKeyknoxData = response

                    completion(cloudEntry, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    @objc open func retrieveEntry(withName name: String) -> CloudEntry? {
        return self.cache[name]
    }

    @objc open func retrieveAllEntries() -> [CloudEntry] {
        return [CloudEntry](self.cache.values)
    }

    @objc open func existsEntry(withName name: String) -> Bool {
        return self.cache[name] != nil
    }

    open func deleteEntry(withName name: String) -> GenericOperation<Void> {
        return self.deleteEntries(withNames: [name])
    }

    open func deleteEntries(withNames names: [String]) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                for name in names {
                    guard self.cache[name] != nil else {
                        completion(nil, CloudKeyStorageError.entryNotFound)
                        return
                    }
                }

                do {
                    for name in names {
                        self.cache.removeValue(forKey: name)
                    }

                    let data = try self.cloudEntrySerializer.serialize(dict: self.cache)

                    let response = try self.keyknoxManager
                        .pushValue(data, previousHash: self.decryptedKeyknoxData?.keyknoxHash)
                        .startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.parse(data: response.value)
                    self.decryptedKeyknoxData = response

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    open func deleteAllEntries() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    self.cache = [:]

                    let data = try self.cloudEntrySerializer.serialize(dict: self.cache)

                    let response = try self.keyknoxManager
                        .pushValue(data, previousHash: self.decryptedKeyknoxData?.keyknoxHash)
                        .startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.parse(data: response.value)
                    self.decryptedKeyknoxData = response

                    completion((), nil)
                }
                catch {
                    completion(nil, error)
                }
            }
        }
    }

    open func updateRecipients(newPublicKeys: [PublicKey]? = nil,
                               newPrivateKey: PrivateKey? = nil) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let response = try self.keyknoxManager
                        .updateRecipients(newPublicKeys: newPublicKeys, newPrivateKey: newPrivateKey)
                        .startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.parse(data: response.value)
                    self.decryptedKeyknoxData = response

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

    open func retrieveCloudEntries() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let response = try self.keyknoxManager.pullValue().startSync().getResult()

                    self.cache = try self.cloudEntrySerializer.parse(data: response.value)
                    self.decryptedKeyknoxData = response

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
}
