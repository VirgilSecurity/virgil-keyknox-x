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

extension KeyknoxManager {
    open func pushData(_ data: Data, publicKeys: [PublicKey],
                       privateKey: PrivateKey) -> GenericOperation<DecryptedKeyknoxData> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxData> = { force in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                let extractDataOperations = self.makeExtractDataOperation(data: data)
                let encryptOperation = self.makeEncryptOperation(publicKeys: publicKeys, privateKey: privateKey)
                let pushValueOperation = self.makePushValueOperation()
                let decryptOperation = self.makeDecryptOperation(publicKeys: publicKeys, privateKey: privateKey)

                encryptOperation.addDependency(extractDataOperations)
                pushValueOperation.addDependency(encryptOperation)
                pushValueOperation.addDependency(getTokenOperation)
                decryptOperation.addDependency(pushValueOperation)

                let operations = [getTokenOperation, extractDataOperations, encryptOperation, pushValueOperation,
                                  decryptOperation]
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                operations.forEach {
                    completionOperation.addDependency($0)
                }

                let queue = OperationQueue()
                queue.addOperations(operations + [completionOperation], waitUntilFinished: false)
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    open func pullData(publicKeys: [PublicKey],
                       privateKey: PrivateKey) -> GenericOperation<DecryptedKeyknoxData> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxData> = { force in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "keyknox", operation: "get", forceReload: force)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                let pullValueOperation = self.makePullValueOperation()
                let decryptOperation = self.makeDecryptOperation(publicKeys: publicKeys, privateKey: privateKey)

                pullValueOperation.addDependency(getTokenOperation)
                decryptOperation.addDependency(pullValueOperation)

                let operations = [getTokenOperation, pullValueOperation, decryptOperation]
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                operations.forEach {
                    completionOperation.addDependency($0)
                }

                let queue = OperationQueue()
                queue.addOperations(operations + [completionOperation], waitUntilFinished: false)
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    open func updateRecipients(publicKeys: [PublicKey], privateKey: PrivateKey,
                               newPublicKeys: [PublicKey]? = nil,
                               newPrivateKey: PrivateKey? = nil) -> GenericOperation<DecryptedKeyknoxData> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxData> = { force in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                let pullValueOperation = self.makePullValueOperation()
                let decryptOperation = self.makeDecryptOperation(publicKeys: publicKeys, privateKey: privateKey)
                let extractDataOperation = self.makeExtractDataOperation()
                let encryptOperation = self.makeEncryptOperation(publicKeys: newPublicKeys ?? publicKeys,
                                                                 privateKey: newPrivateKey ?? privateKey)
                let pushValueOperation = self.makePushValueOperation()
                let decryptOperation2 = self.makeDecryptOperation(publicKeys: newPublicKeys ?? publicKeys,
                                                                  privateKey: newPrivateKey ?? privateKey)

                pullValueOperation.addDependency(getTokenOperation)
                decryptOperation.addDependency(pullValueOperation)
                extractDataOperation.addDependency(decryptOperation)
                encryptOperation.addDependency(extractDataOperation)
                pushValueOperation.addDependency(getTokenOperation)
                pushValueOperation.addDependency(encryptOperation)
                decryptOperation2.addDependency(pushValueOperation)

                let operations = [getTokenOperation, pullValueOperation, decryptOperation,
                                  extractDataOperation, encryptOperation, pushValueOperation, decryptOperation2]
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                operations.forEach {
                    completionOperation.addDependency($0)
                }

                let queue = OperationQueue()
                queue.addOperations(operations + [completionOperation], waitUntilFinished: false)
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    open func updateRecipients(data: Data, newPublicKeys: [PublicKey],
                               newPrivateKey: PrivateKey) -> GenericOperation<DecryptedKeyknoxData> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxData> = { force in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                let extractDataOperation = self.makeExtractDataOperation(data: data)
                let encryptOperation = self.makeEncryptOperation(publicKeys: newPublicKeys, privateKey: newPrivateKey)
                let pushValueOperation = self.makePushValueOperation()
                let decryptOperation = self.makeDecryptOperation(publicKeys: newPublicKeys, privateKey: newPrivateKey)

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
                queue.addOperations(operations + [completionOperation], waitUntilFinished: false)
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
