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

@interface VSK002_KeyknoxManagerTests : XCTestCase

@property (nonatomic) TestConfig *config;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VSKKeyknoxManager *keyknoxManager;
@property (nonatomic) NSInteger numberOfKeys;

@end

@implementation VSK002_KeyknoxManagerTests

- (void)setUp {
    [super setUp];
    
    self.config = [TestConfig readFromBundle];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:true];
    VSKKeyknoxClient *keyknoxClient = [[VSKKeyknoxClient alloc] initWithServiceUrl:[[NSURL alloc] initWithString:self.config.ServiceURL]];
    
    VSMVirgilPrivateKey *apiKey = [self.crypto importPrivateKeyFrom:[[NSData alloc] initWithBase64EncodedString:self.config.ApiPrivateKey options:0] password:nil error:nil];
    VSSJwtGenerator *generator = [[VSSJwtGenerator alloc] initWithApiKey:apiKey apiPublicKeyIdentifier:self.config.ApiPublicKeyId accessTokenSigner:[[VSMVirgilAccessTokenSigner alloc] initWithVirgilCrypto:self.crypto] appId:self.config.AppId ttl:600];
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    
    id<VSSAccessTokenProvider> provider = [[VSSCachingJwtProvider alloc] initWithRenewJwtCallback:^(VSSTokenContext *context, void (^completion)(VSSJwt *jwt, NSError *error)) {
        VSSJwt *jwt = [generator generateTokenWithIdentity:identity additionalData:nil error:nil];
        
        completion(jwt, nil);
    }];
    
    self.keyknoxManager = [[VSKKeyknoxManager alloc] initWithAccessTokenProvider:provider keyknoxClient:keyknoxClient];
    
    self.numberOfKeys = 4;
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_pushValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    
    [self.keyknoxManager pushData:someData publicKeys:@[keyPair.publicKey] privateKey:keyPair.privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        
        XCTAssert([decryptedData.data isEqualToData:someData]);
        
        [ex fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test002_pullValue {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
    
    [self.keyknoxManager pushData:someData publicKeys:@[keyPair.publicKey] privateKey:keyPair.privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
        [self.keyknoxManager pullDataWithPublicKeys:@[keyPair.publicKey] privateKey:keyPair.privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.data isEqualToData:someData]);
            
            [ex fulfill];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test003_pullMultiplePublicKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    VSMVirgilPrivateKey *privateKey = nil;
    NSMutableArray<VSMVirgilPublicKey *> *halfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *anotherHalfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    
    for (int i = 0; i < self.numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        
        if (i == 0)
            privateKey = keyPair.privateKey;
        
        if (i < self.numberOfKeys / 2)
            [halfPublicKeys addObject:keyPair.publicKey];
        else
            [anotherHalfPublicKeys addObject:keyPair.publicKey];
    }
    
    [self.keyknoxManager pushData:someData publicKeys:halfPublicKeys privateKey:privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert([decryptedData.data isEqualToData:someData]);

        [self.keyknoxManager pullDataWithPublicKeys:halfPublicKeys privateKey:privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.data isEqualToData:someData]);

            [self.keyknoxManager pullDataWithPublicKeys:anotherHalfPublicKeys privateKey:privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
                XCTAssert(decryptedData == nil && error != nil);
                XCTAssert([error.domain isEqualToString:VSKKeyknoxManagerErrorDomain]);
                XCTAssert(error.code == VSKKeyknoxManagerErrorSignerNotFound);
                
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test004_pullDifferentPrivateKeys {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableArray<VSMVirgilKeyPair *> *keyPairs = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *publicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *halfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    
    for (int i = 0; i < self.numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        
        [keyPairs addObject:keyPair];
        [publicKeys addObject:keyPair.publicKey];
        
        if (i < self.numberOfKeys / 2)
            [halfPublicKeys addObject:keyPair.publicKey];
    }
    
    VSCVirgilRandom *random = [[VSCVirgilRandom alloc] initWithPersonalInfo:@"info"];
    
    size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];
    
    [self.keyknoxManager pushData:someData publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert([decryptedData.data isEqualToData:someData]);
        
        size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];
        [self.keyknoxManager pullDataWithPublicKeys:publicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.data isEqualToData:someData]);
            
            size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];
            [self.keyknoxManager pullDataWithPublicKeys:publicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
                XCTAssert(decryptedData == nil && error != nil);
                XCTAssert([error.domain isEqualToString:VSKKeyknoxManagerErrorDomain]);
                XCTAssert(error.code == VSKKeyknoxManagerErrorDecryptionFailed);
                
                [ex fulfill];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test005_updateRecipients {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableArray<VSMVirgilKeyPair *> *keyPairs = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *publicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *halfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *anotherHalfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    
    for (int i = 0; i < self.numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        
        [keyPairs addObject:keyPair];
        [publicKeys addObject:keyPair.publicKey];
        
        if (i < self.numberOfKeys / 2)
            [halfPublicKeys addObject:keyPair.publicKey];
        else
            [anotherHalfPublicKeys addObject:keyPair.publicKey];
    }
    
    VSCVirgilRandom *random = [[VSCVirgilRandom alloc] initWithPersonalInfo:@"info"];
    
    size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];
    
    [self.keyknoxManager pushData:someData publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert([decryptedData.data isEqualToData:someData]);
        
        size_t rand1 = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];
        size_t rand2 = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];
        
        [self.keyknoxManager updateRecipientsWithPublicKeys:publicKeys privateKey:keyPairs[rand1].privateKey newPublicKeys:anotherHalfPublicKeys newPrivateKey:keyPairs[rand2].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.data isEqualToData:someData]);

            size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];

            [self.keyknoxManager pullDataWithPublicKeys:anotherHalfPublicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
                XCTAssert(decryptedData != nil && error == nil);
                XCTAssert([decryptedData.data isEqualToData:someData]);
                
                size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];
                
                [self.keyknoxManager pullDataWithPublicKeys:anotherHalfPublicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
                    XCTAssert(decryptedData == nil && error != nil);
                    XCTAssert([error.domain isEqualToString:VSKKeyknoxManagerErrorDomain]);
                    XCTAssert(error.code == VSKKeyknoxManagerErrorDecryptionFailed);
                    
                    size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];
                    
                    [self.keyknoxManager pullDataWithPublicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
                        XCTAssert(decryptedData == nil && error != nil);
                        XCTAssert([error.domain isEqualToString:VSKKeyknoxManagerErrorDomain]);
                        XCTAssert(error.code == VSKKeyknoxManagerErrorSignerNotFound);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test006_updateRecipientsWithData {
    XCTestExpectation *ex = [self expectationWithDescription:@""];
    
    NSData *someData = [[[NSUUID alloc] init].UUIDString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableArray<VSMVirgilKeyPair *> *keyPairs = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *publicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *halfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    NSMutableArray<VSMVirgilPublicKey *> *anotherHalfPublicKeys = [[NSMutableArray alloc] initWithCapacity:self.numberOfKeys];
    
    for (int i = 0; i < self.numberOfKeys; i++) {
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSCKeyTypeFAST_EC_ED25519 error:nil];
        
        [keyPairs addObject:keyPair];
        [publicKeys addObject:keyPair.publicKey];
        
        if (i < self.numberOfKeys / 2)
            [halfPublicKeys addObject:keyPair.publicKey];
        else
            [anotherHalfPublicKeys addObject:keyPair.publicKey];
    }
    
    VSCVirgilRandom *random = [[VSCVirgilRandom alloc] initWithPersonalInfo:@"info"];
    
    size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];
    
    [self.keyknoxManager pushData:someData publicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
        XCTAssert(decryptedData != nil && error == nil);
        XCTAssert([decryptedData.data isEqualToData:someData]);
        
        size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];
        
        [self.keyknoxManager updateRecipientsWithData:decryptedData.data newPublicKeys:anotherHalfPublicKeys newPrivateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
            XCTAssert(decryptedData != nil && error == nil);
            XCTAssert([decryptedData.data isEqualToData:someData]);
            
            size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];
            
            [self.keyknoxManager pullDataWithPublicKeys:anotherHalfPublicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
                XCTAssert(decryptedData != nil && error == nil);
                XCTAssert([decryptedData.data isEqualToData:someData]);
                
                size_t rand = [random randomizeBetweenMin:0 andMax:self.numberOfKeys / 2 - 1];
                
                [self.keyknoxManager pullDataWithPublicKeys:anotherHalfPublicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
                    XCTAssert(decryptedData == nil && error != nil);
                    XCTAssert([error.domain isEqualToString:VSKKeyknoxManagerErrorDomain]);
                    XCTAssert(error.code == VSKKeyknoxManagerErrorDecryptionFailed);
                    
                    size_t rand = [random randomizeBetweenMin:self.numberOfKeys / 2 andMax:self.numberOfKeys - 1];
                    
                    [self.keyknoxManager pullDataWithPublicKeys:halfPublicKeys privateKey:keyPairs[rand].privateKey completion:^(VSKDecryptedKeyknoxData *decryptedData, NSError *error) {
                        XCTAssert(decryptedData == nil && error != nil);
                        XCTAssert([error.domain isEqualToString:VSKKeyknoxManagerErrorDomain]);
                        XCTAssert(error.code == VSKKeyknoxManagerErrorSignerNotFound);
                        
                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];
    
    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
