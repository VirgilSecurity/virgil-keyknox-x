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
}

@objc(VSKKeyknoxManager) open class KeyknoxManager: NSObject {
    /// AccessTokenProvider instance used for getting Access Token
    /// when performing queries
    @objc public let accessTokenProvider: AccessTokenProvider
    /// KeyknoxClient instance used for performing queries
    @objc public let keyknoxClient: KeyknoxClientProtocol
    public let crypto: KeyknoxCryptoProtocol
    @objc public let retryOnUnauthorized: Bool
    @objc private(set) public var previousHash: Data? = nil

    @objc public init(accessTokenProvider: AccessTokenProvider,
                      keyknoxClient: KeyknoxClientProtocol = KeyknoxClient(),
                      retryOnUnauthorized: Bool = false) {
        self.accessTokenProvider = accessTokenProvider
        self.keyknoxClient = keyknoxClient
        self.crypto = KeyknoxCrypto()
        self.retryOnUnauthorized = retryOnUnauthorized

        super.init()
    }
}

internal extension KeyknoxManager {
    internal func makePullValueOperation() -> GenericOperation<EncryptedKeyknoxData> {
        return CallbackOperation { operation, completion in
            do {
                let token: AccessToken = try operation.findDependencyResult()

                let response = try self.keyknoxClient.pullValue(token: token.stringRepresentation())

                self.previousHash = response.keyknoxHash

                completion(response, nil)
            }
            catch let error as ServiceError
                where error.httpStatusCode == 404 && error.errorCode == KeyknoxClientError.entityNotFound.rawValue {
                    completion(nil, KeyknoxManagerError.keyknoxIsEmpty)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    internal func makePushValueOperation() -> GenericOperation<EncryptedKeyknoxData> {
        return CallbackOperation { operation, completion in
            do {
                let token: AccessToken = try operation.findDependencyResult()
                let data: (Data, Data) = try operation.findDependencyResult()

                let response = try self.keyknoxClient.pushValue(meta: data.0, value: data.1,
                                                                previousHash: self.previousHash,
                                                                token: token.stringRepresentation())
                self.previousHash = response.keyknoxHash

                completion(response, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
}
