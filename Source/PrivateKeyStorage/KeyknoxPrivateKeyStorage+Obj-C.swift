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

@objc(VSKKeyEntry) public final class KeyEntry: NSObject {
    @objc public let key: VirgilPrivateKey
    @objc public let name: String

    @objc public init(key: VirgilPrivateKey, name: String) {
        self.key = key
        self.name = name

        super.init()
    }
}

extension KeyknoxPrivateKeyStorage {
    @objc open func sync(completion: @escaping (Error?) -> ()) {
        self.sync().start { _, error in
            completion(error)
        }
    }

    @objc open func store(keyEntries: [KeyEntry], completion: @escaping (Error?) -> ()) {
        self.store(keyEntries: keyEntries.map { ($0.key, $0.name) }).start { _, error in
            completion(error)
        }
    }

    @objc open func store(privateKey: VirgilPrivateKey, withName name: String,
                          completion: @escaping (Error?) -> ()) {
        self.store(privateKey: privateKey, withName: name).start { _, error in
            completion(error)
        }
    }

    @objc open func deleteKey(withName name: String, completion: @escaping (Error?) -> ()) {
        self.deleteKey(withName: name).start { _, error in
            completion(error)
        }
    }

    @objc open func deleteKeys(withNames names: [String], completion: @escaping (Error?) -> ()) {
        self.deleteKeys(withNames: names).start { _, error in
            completion(error)
        }
    }

    @objc open func deleteAllKeys(completion: @escaping (Error?) -> ()) {
        self.deleteAllKeys().start { _, error in
            completion(error)
        }
    }
}
