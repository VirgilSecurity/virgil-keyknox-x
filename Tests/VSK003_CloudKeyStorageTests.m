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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
@import VirgilSDK;
@import VirgilSDKKeyknox;
@import VirgilCrypto;
@import VirgilCryptoApiImpl;
#import "VirgilSDKKeyknox_iOS_Tests-Swift.h"

static const NSTimeInterval timeout = 20.;

@interface VSK003_CloudKeyStorageTests : XCTestCase

@property (nonatomic) TestConfig *config;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSKCloudKeyStorage *keyStorage;
@property (nonatomic) NSInteger numberOfKeys;

@end

@implementation VSK003_CloudKeyStorageTests

- (void)setUp {
    [super setUp];
    
    self.config = [TestConfig readFromBundle];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:NO];
    VSKKeyknoxClient *keyknoxClient = [[VSKKeyknoxClient alloc] initWithServiceUrl:[[NSURL alloc] initWithString:self.config.ServiceURL]];
    
    VSMVirgilPrivateKey *apiKey = [self.crypto importPrivateKeyFrom:[[NSData alloc] initWithBase64EncodedString:self.config.ApiPrivateKey options:0] password:nil error:nil];
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:apiKey apiPublicKeyIdentifier:self.config.ApiPublicKeyId accessTokenSigner:[[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto] appId:self.config.AppId ttl:600];
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    
    id<VSSAccessTokenProvider> provider = [[VSSCachingJwtProvider alloc] initWithRenewJwtCallback:^(VSSTokenContext *context, void (^completion)(VSSJwt *jwt, NSError *error)) {
        VSSJwt *jwt = [generator generateTokenWithIdentity:identity additionalData:nil error:nil];
        
        completion(jwt, nil);
    }];

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];

    NSError *err;
    
    VSKKeyknoxManager *keyknoxManager = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:provider keyknoxClient:keyknoxClient publicKeys:@[keyPair.publicKey] privateKey:keyPair.privateKey retryOnUnauthorized:NO error:&err];
    
    XCTAssert(err == nil);
    
    self.keyStorage = [[VSKCloudKeyStorage alloc] initWithKeyknoxManager:keyknoxManager];
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_retrieveCloudEntriesEmptyKeyknox {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        NSError *err;
        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
        XCTAssert(err == nil);
        
        [ex fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test002_storeKey {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];
    NSString *name = @"test";
    NSDictionary *meta = @{
                           @"test_key": @"test_value"
                           };
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntryWithName:name data:privateKeyData meta:meta completion:^(NSError *error) {
            XCTAssert(error == nil);
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
            XCTAssert(err == nil);
            
            VSKCloudEntry *entry = [self.keyStorage retrieveEntryWithName:name error:&err];
            XCTAssert(err == nil);
            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:entry.data password:nil error:nil];
            XCTAssert([privateKey.identifier isEqualToData:keyPair.privateKey.identifier]);
            XCTAssert([entry.name isEqualToString:name]);
            XCTAssert(entry.creationDate.timeIntervalSinceNow < 5);
            XCTAssert([entry.creationDate isEqualToDate:entry.modificationDate]);
            XCTAssert([entry.meta isEqualToDictionary:meta]);
            
            [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
                XCTAssert(err == nil);
                
                VSKCloudEntry *entry = [self.keyStorage retrieveEntryWithName:name error:&err];
                XCTAssert(err == nil);
                VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:entry.data password:nil error:nil];
                XCTAssert([privateKey.identifier isEqualToData:keyPair.privateKey.identifier]);
                XCTAssert([entry.name isEqualToString:name]);
                XCTAssert(entry.creationDate.timeIntervalSinceNow < 5);
                XCTAssert([entry.creationDate isEqualToDate:entry.modificationDate]);
                XCTAssert([entry.meta isEqualToDictionary:meta]);
                
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test003_existsKey {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];

    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntryWithName:@"test" data:privateKeyData meta:nil completion:^(NSError *error) {
            XCTAssert(error == nil);
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
            XCTAssert(err == nil);

            XCTAssert([self.keyStorage existsEntryNoThrowWithName:@"test"]);

            [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
                XCTAssert(err == nil);

                XCTAssert([self.keyStorage existsEntryNoThrowWithName:@"test"]);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test004_storeMultipleKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    int numberOfKeys = 100;

    NSMutableArray<VSMVirgilPrivateKey *> *privateKeys = [[NSMutableArray alloc] init];
    NSMutableArray<VSKKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];

    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];

        [privateKeys addObject:keyPair.privateKey];

        if (i > 0 && i < numberOfKeys - 1) {
            NSString *name = [NSString stringWithFormat:@"%d", i];
            NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey];
            VSKKeyEntry *keyEntry = [[VSKKeyEntry alloc] initWithName:name data:data meta:nil];
            [keyEntries addObject:keyEntry];
        }
    }

    NSData *privateKeyData = [self.crypto exportPrivateKey:privateKeys[0]];
    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntryWithName:@"first" data:privateKeyData meta:nil completion:^(NSError *error) {
            XCTAssert(error == nil);
            NSError *err;
            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 1);
            XCTAssert(err == nil);
            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data password:nil error:nil];
            XCTAssert(err == nil);
            XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);

            [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 1);
                XCTAssert(err == nil);
                VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data password:nil error:nil];
                XCTAssert(err == nil);
                XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                for (int i = 1; i < numberOfKeys - 1; i++) {
                    NSString *name = [NSString stringWithFormat:@"%d", i];
                    VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data password:nil error:nil];
                    XCTAssert(err == nil);
                    XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                }

                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys - 1);
                    XCTAssert(err == nil);
                    VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data password:nil error:nil];
                    XCTAssert(err == nil);
                    XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                    for (int i = 1; i < numberOfKeys - 1; i++) {
                        NSString *name = [NSString stringWithFormat:@"%d", i];
                        VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data password:nil error:nil];
                        XCTAssert(err == nil);
                        XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                    }

                    NSData *privateKeyData = [self.crypto exportPrivateKey:privateKeys[numberOfKeys - 1]];
                    [self.keyStorage storeEntryWithName:@"last" data:privateKeyData meta:nil completion:^(NSError *error) {
                        XCTAssert(error == nil);
                        NSError *err;
                        XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                        XCTAssert(err == nil);
                        VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data password:nil error:nil];
                        XCTAssert(err == nil);
                        XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                        for (int i = 1; i < numberOfKeys - 1; i++) {
                            NSString *name = [NSString stringWithFormat:@"%d", i];
                            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data password:nil error:nil];
                            XCTAssert(err == nil);
                            XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                        }
                        VSMVirgilPrivateKey *lastPrivateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"last" error:&err].data password:nil error:nil];
                        XCTAssert(err == nil);
                        XCTAssert([lastPrivateKey.identifier isEqualToData:privateKeys[numberOfKeys - 1].identifier]);

                        [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                            XCTAssert(error == nil);
                            NSError *err;
                            XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == numberOfKeys);
                            XCTAssert(err == nil);
                            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"first" error:&err].data password:nil error:nil];
                            XCTAssert(err == nil);
                            XCTAssert([privateKey.identifier isEqualToData:privateKeys[0].identifier]);
                            for (int i = 1; i < numberOfKeys - 1; i++) {
                                NSString *name = [NSString stringWithFormat:@"%d", i];
                                VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:name error:&err].data password:nil error:nil];
                                XCTAssert(err == nil);
                                XCTAssert([privateKey.identifier isEqualToData:privateKeys[i].identifier]);
                            }
                            VSMVirgilPrivateKey *lastPrivateKey = [self.crypto importPrivateKeyFrom:[self.keyStorage retrieveEntryWithName:@"last" error:&err].data password:nil error:nil];
                            XCTAssert(err == nil);
                            XCTAssert([lastPrivateKey.identifier isEqualToData:privateKeys[numberOfKeys - 1].identifier]);

                            [ex fulfill];
                        }];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test005_deleteAllKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];

    int numberOfKeys = 100;

    NSMutableArray<VSKKeyEntry *> *keyEntries = [[NSMutableArray alloc] init];

    for (int i = 0; i < numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        NSString *name = [NSString stringWithFormat:@"%d", i];
        NSData *privateKeyData = [self.crypto exportPrivateKey:keyPair.privateKey];
        VSKKeyEntry *keyEntry = [[VSKKeyEntry alloc] initWithName:name data:privateKeyData meta:nil];
        [keyEntries addObject:keyEntry];
    }

    [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
        [self.keyStorage storeEntries:keyEntries completion:^(NSError *error) {
            [self.keyStorage deleteAllEntriesWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);
                NSError *err;
                XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
                XCTAssert(err == nil);

                [self.keyStorage retrieveCloudEntriesWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);
                    NSError *err;
                    XCTAssert([self.keyStorage retrieveAllEntriesAndReturnError:&err].count == 0);
                    XCTAssert(err == nil);

                    [ex fulfill];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout + numberOfKeys / 4 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
