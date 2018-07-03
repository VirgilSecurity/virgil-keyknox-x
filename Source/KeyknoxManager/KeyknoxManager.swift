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
import VirgilCryptoAPI

/// Declares error types and codes for CardManager
@objc(VSKKeyknoxManagerError) public enum KeyknoxManagerError: Int, Error {
    case signerNotFound = 1
    case signatureVerificationFailed = 2
    case decryptionFailed = 3
    case keyknoxIsEmpty = 4
    case noPublicKeys = 5
    case keysShouldBeUpdated = 6
    case serverRespondedWithTamperedValue = 7
}

@objc(VSKKeyknoxManager) open class KeyknoxManager: NSObject {
    /// AccessTokenProvider instance used for getting Access Token
    /// when performing queries
    @objc public let accessTokenProvider: AccessTokenProvider
    /// KeyknoxClient instance used for performing queries
    @objc public let keyknoxClient: KeyknoxClientProtocol
    @objc private(set) public var publicKeys: [PublicKey]
    @objc private(set) public var privateKey: PrivateKey
    public let crypto: KeyknoxCryptoProtocol
    @objc public let retryOnUnauthorized: Bool

    private let queue = DispatchQueue(label: "KeyknoxManagerQueue")

    public init(accessTokenProvider: AccessTokenProvider,
                keyknoxClient: KeyknoxClientProtocol = KeyknoxClient(),
                publicKeys: [PublicKey], privateKey: PrivateKey,
                crypto: KeyknoxCryptoProtocol = KeyknoxCrypto(),
                retryOnUnauthorized: Bool = false) throws {
        guard !publicKeys.isEmpty else {
            throw KeyknoxManagerError.noPublicKeys
        }

        self.accessTokenProvider = accessTokenProvider
        self.keyknoxClient = keyknoxClient
        self.publicKeys = publicKeys
        self.privateKey = privateKey
        self.crypto = crypto
        self.retryOnUnauthorized = retryOnUnauthorized

        super.init()
    }

    @objc public convenience init(accessTokenProvider: AccessTokenProvider,
                                  keyknoxClient: KeyknoxClientProtocol = KeyknoxClient(),
                                  publicKeys: [PublicKey], privateKey: PrivateKey,
                                  retryOnUnauthorized: Bool = false) throws {
        try self.init(accessTokenProvider: accessTokenProvider,
                      keyknoxClient: keyknoxClient,
                      publicKeys: publicKeys, privateKey: privateKey,
                      crypto: KeyknoxCrypto(),
                      retryOnUnauthorized: retryOnUnauthorized)
    }
}

internal extension KeyknoxManager {
    internal func makePullValueOperation() -> GenericOperation<EncryptedKeyknoxValue> {
        return CallbackOperation { operation, completion in
            do {
                let token: AccessToken = try operation.findDependencyResult()

                let response = try self.keyknoxClient.pullValue(token: token.stringRepresentation())

                completion(response, nil)
            }
            catch let error as ServiceError
                where error.httpStatusCode == 404 && error.errorCode == 50002 {
                    completion(nil, KeyknoxManagerError.keyknoxIsEmpty)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    internal func makePushValueOperation() -> GenericOperation<EncryptedKeyknoxValue> {
        return CallbackOperation { operation, completion in
            do {
                let token: AccessToken = try operation.findDependencyResult()
                let data: (Data, Data) = try operation.findDependencyResult()
                let encryptedKeyknoxData: DecryptedKeyknoxValue = try operation.findDependencyResult()

                let response = try self.keyknoxClient.pushValue(meta: data.0, value: data.1,
                                                                previousHash: encryptedKeyknoxData.keyknoxHash,
                                                                token: token.stringRepresentation())

                guard response.value == data.1 && response.meta == data.0 else {
                    throw KeyknoxManagerError.serverRespondedWithTamperedValue
                }

                completion(response, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    internal func makePushValueOperation(previousHash: Data?) -> GenericOperation<EncryptedKeyknoxValue> {
        return CallbackOperation { operation, completion in
            do {
                let token: AccessToken = try operation.findDependencyResult()
                let data: (Data, Data) = try operation.findDependencyResult()

                let response = try self.keyknoxClient.pushValue(meta: data.0, value: data.1,
                                                                previousHash: previousHash,
                                                                token: token.stringRepresentation())

                guard response.value == data.1 && response.meta == data.0 else {
                    throw KeyknoxManagerError.serverRespondedWithTamperedValue
                }

                completion(response, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
}

extension KeyknoxManager {
    open func pushValue(_ value: Data, previousHash: Data?) -> GenericOperation<DecryptedKeyknoxValue> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxValue> = { force in
            return CallbackOperation { _, completion in
                self.queue.async {
                    let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                    let getTokenOperation = OperationUtils.makeGetTokenOperation(
                        tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                    let extractDataOperations = self.makeExtractDataOperation(data: value)
                    let encryptOperation = self.makeEncryptOperation()
                    let pushValueOperation = self.makePushValueOperation(previousHash: previousHash)
                    let decryptOperation = self.makeDecryptOperation()

                    encryptOperation.addDependency(extractDataOperations)
                    pushValueOperation.addDependency(encryptOperation)
                    pushValueOperation.addDependency(getTokenOperation)
                    decryptOperation.addDependency(pushValueOperation)

                    let operations = [getTokenOperation, extractDataOperations,
                                      encryptOperation, pushValueOperation, decryptOperation]
                    let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                    operations.forEach {
                        completionOperation.addDependency($0)
                    }

                    let queue = OperationQueue()
                    queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
                }
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    open func pullValue() -> GenericOperation<DecryptedKeyknoxValue> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxValue> = { force in
            return CallbackOperation { _, completion in
                self.queue.async {
                    let tokenContext = TokenContext(service: "keyknox", operation: "get", forceReload: force)
                    let getTokenOperation = OperationUtils.makeGetTokenOperation(
                        tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                    let pullValueOperation = self.makePullValueOperation()
                    let decryptOperation = self.makeDecryptOperation()

                    pullValueOperation.addDependency(getTokenOperation)
                    decryptOperation.addDependency(pullValueOperation)

                    let operations = [getTokenOperation, pullValueOperation, decryptOperation]
                    let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                    operations.forEach {
                        completionOperation.addDependency($0)
                    }

                    let queue = OperationQueue()
                    queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
                }
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    open func updateRecipients(newPublicKeys: [PublicKey]? = nil,
                               newPrivateKey: PrivateKey? = nil) -> GenericOperation<DecryptedKeyknoxValue> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxValue> = { force in
            return CallbackOperation { _, completion in
                self.queue.async {
                    guard newPublicKeys != nil || newPrivateKey != nil else {
                        completion(nil, KeyknoxManagerError.keysShouldBeUpdated)
                        return
                    }

                    let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                    let getTokenOperation = OperationUtils.makeGetTokenOperation(
                        tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                    let pullValueOperation = self.makePullValueOperation()
                    let decryptOperation = self.makeDecryptOperation()
                    let extractDataOperation = self.makeExtractDataOperation()
                    let encryptOperation = self.makeEncryptOperation(newPublicKeys: newPublicKeys,
                                                                     newPrivateKey: newPrivateKey)
                    let pushValueOperation = self.makePushValueOperation()
                    let decryptOperation2 = self.makeDecryptOperation()

                    pullValueOperation.addDependency(getTokenOperation)
                    decryptOperation.addDependency(pullValueOperation)
                    extractDataOperation.addDependency(decryptOperation)
                    encryptOperation.addDependency(extractDataOperation)
                    pushValueOperation.addDependency(getTokenOperation)
                    pushValueOperation.addDependency(decryptOperation)
                    pushValueOperation.addDependency(encryptOperation)
                    decryptOperation2.addDependency(pushValueOperation)

                    let operations = [getTokenOperation, pullValueOperation, decryptOperation,
                                      extractDataOperation, encryptOperation, pushValueOperation, decryptOperation2]
                    let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                    operations.forEach {
                        completionOperation.addDependency($0)
                    }

                    let queue = OperationQueue()
                    queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
                }
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    open func updateRecipients(value: Data, previousHash: Data,
                               newPublicKeys: [PublicKey]? = nil,
                               newPrivateKey: PrivateKey? = nil) -> GenericOperation<DecryptedKeyknoxValue> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxValue> = { force in
            return CallbackOperation { _, completion in
                self.queue.async {
                    let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                    let getTokenOperation = OperationUtils.makeGetTokenOperation(
                        tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                    let extractDataOperation = self.makeExtractDataOperation(data: value)
                    let encryptOperation = self.makeEncryptOperation(newPublicKeys: newPublicKeys,
                                                                     newPrivateKey: newPrivateKey)
                    let pushValueOperation = self.makePushValueOperation(previousHash: previousHash)
                    let decryptOperation = self.makeDecryptOperation()

                    encryptOperation.addDependency(extractDataOperation)
                    pushValueOperation.addDependency(getTokenOperation)
                    pushValueOperation.addDependency(encryptOperation)
                    decryptOperation.addDependency(pushValueOperation)

                    let operations = [extractDataOperation, encryptOperation, getTokenOperation,
                                      pushValueOperation, decryptOperation]
                    let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                    operations.forEach {
                        completionOperation.addDependency($0)
                    }

                    let queue = OperationQueue()
                    queue.addOperations(operations + [completionOperation], waitUntilFinished: true)
                }
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }
}

extension KeyknoxManager {
    private func makeDecryptOperation() -> GenericOperation<DecryptedKeyknoxValue> {
        return CallbackOperation { operation, completion in
            do {
                let keyknoxData: EncryptedKeyknoxValue = try operation.findDependencyResult()

                let result = try self.crypto.decrypt(encryptedKeyknoxValue: keyknoxData,
                                                     privateKey: self.privateKey, publicKeys: self.publicKeys)

                completion(result, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    private func makeExtractDataOperation(data: Data? = nil) -> GenericOperation<Data> {
        return CallbackOperation { operation, completion in
            if let data = data {
                completion(data, nil)
                return
            }

            do {
                let data: DecryptedKeyknoxValue = try operation.findDependencyResult()
                completion(data.value, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    private func makeEncryptOperation(newPublicKeys: [PublicKey]? = nil,
                                      newPrivateKey: PrivateKey? = nil) -> GenericOperation<(Data, Data)> {
        return CallbackOperation { operation, completion in
            do {
                let data: Data = try operation.findDependencyResult()

                if let newPublicKeys = newPublicKeys {
                    guard !newPublicKeys.isEmpty else {
                        throw KeyknoxManagerError.noPublicKeys
                    }
                    self.publicKeys = newPublicKeys
                }
                if let newPrivateKey = newPrivateKey {
                    self.privateKey = newPrivateKey
                }

                completion(try self.crypto.encrypt(data: data, privateKey: self.privateKey,
                                                   publicKeys: self.publicKeys), nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
}
