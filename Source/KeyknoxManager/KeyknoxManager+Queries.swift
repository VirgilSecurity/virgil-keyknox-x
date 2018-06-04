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
import VirgilCrypto
import VirgilCryptoApiImpl
import VirgilSDK

extension KeyknoxManager {
    open func pushData(data: Data, publicKeys: [VirgilPublicKey],
                       privateKey: VirgilPrivateKey) -> GenericOperation<EncryptedKeyknoxData> {
        let makeAggregateOperation: (Bool) -> GenericOperation<EncryptedKeyknoxData> = { force in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                
                let extractDataOperations = self.makeExtractDataOperation(data: data)
                
                let encryptOperation = self.makeEncryptOperation(publicKeys: publicKeys, privateKey: privateKey)
                
                let pushValueOperation = self.makePushValueOperation()
                
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                
                encryptOperation.addDependency(extractDataOperations)
                
                pushValueOperation.addDependency(encryptOperation)
                pushValueOperation.addDependency(getTokenOperation)

                completionOperation.addDependency(pushValueOperation)
                
                let queue = OperationQueue()
                let operations = [getTokenOperation, extractDataOperations, encryptOperation, pushValueOperation, completionOperation]
                queue.addOperations(operations, waitUntilFinished: false)
            }
        }
        
        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    open func pullData(publicKeys: [VirgilPublicKey],
                       privateKey: VirgilPrivateKey) -> GenericOperation<DecryptedKeyknoxData> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxData> = { force in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "keyknox", operation: "get", forceReload: force)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)

                let pullValueOperation = self.makePullValueOperation()
                
                let decryptOperation = self.makeDecryptOperation(publicKeys: publicKeys, privateKey: privateKey)

                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

                pullValueOperation.addDependency(getTokenOperation)
                
                decryptOperation.addDependency(pullValueOperation)

                completionOperation.addDependency(decryptOperation)

                let queue = OperationQueue()
                let operations = [getTokenOperation, pullValueOperation, decryptOperation, completionOperation]
                queue.addOperations(operations, waitUntilFinished: false)
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    open func updateRecipients(publicKeys: [VirgilPublicKey],
                               privateKey: VirgilPrivateKey) -> GenericOperation<DecryptedKeyknoxData> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxData> = { force in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)

                let pullValueOperation = self.makePullValueOperation()

                let decryptOperation = self.makeDecryptOperation(publicKeys: publicKeys, privateKey: privateKey)
                
                let extractDataOperation = self.makeExtractDataOperation()
                
                let encryptOperation = self.makeEncryptOperation(publicKeys: publicKeys, privateKey: privateKey)
                
                let pushValueOperation = self.makePushValueOperation()
                
                let decryptOperation2 = self.makeDecryptOperation(publicKeys: publicKeys, privateKey: privateKey)

                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

                pullValueOperation.addDependency(getTokenOperation)
                decryptOperation.addDependency(pullValueOperation)
                extractDataOperation.addDependency(decryptOperation)
                encryptOperation.addDependency(extractDataOperation)
                pushValueOperation.addDependency(encryptOperation)
                decryptOperation2.addDependency(pushValueOperation)
                completionOperation.addDependency(decryptOperation2)

                let queue = OperationQueue()
                let operations = [getTokenOperation, pullValueOperation, decryptOperation,
                                  extractDataOperation, encryptOperation, pushValueOperation, completionOperation]
                queue.addOperations(operations, waitUntilFinished: false)
            }
        }

        if !self.retryOnUnauthorized {
            return makeAggregateOperation(false)
        }
        else {
            return OperationUtils.makeRetryAggregate(makeAggregateOperation: makeAggregateOperation)
        }
    }

    open func updateRecipients(data: Data, publicKeys: [VirgilPublicKey],
                               privateKey: VirgilPrivateKey) -> GenericOperation<DecryptedKeyknoxData> {
        let makeAggregateOperation: (Bool) -> GenericOperation<DecryptedKeyknoxData> = { force in
            return CallbackOperation { _, completion in
                let tokenContext = TokenContext(service: "keyknox", operation: "put", forceReload: force)
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
                
                let extractDataOperation = self.makeExtractDataOperation(data: data)
                
                let encryptOperation = self.makeEncryptOperation(publicKeys: publicKeys, privateKey: privateKey)
                
                let pushValueOperation = self.makePushValueOperation()
                
                let decryptOperation = self.makeDecryptOperation(publicKeys: publicKeys, privateKey: privateKey)
                
                let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
                
                encryptOperation.addDependency(extractDataOperation)
                pushValueOperation.addDependency(encryptOperation)
                decryptOperation.addDependency(pushValueOperation)
                completionOperation.addDependency(decryptOperation)
                
                let queue = OperationQueue()
                let operations = [getTokenOperation, extractDataOperation, encryptOperation,
                                  pushValueOperation, decryptOperation, completionOperation]
                queue.addOperations(operations, waitUntilFinished: false)
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
