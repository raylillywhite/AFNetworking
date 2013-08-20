// AFSecurity.m
//
// Copyright (c) 2013 AFNetworking (http://afnetworking.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "AFSecurity.h"

#if !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
static NSData *AFSecKeyGetData(SecKeyRef key) {
    CFDataRef data = NULL;
    
    OSStatus status = SecItemExport(key, kSecFormatUnknown, kSecItemPemArmour, NULL, &data);
    NSCAssert(status == errSecSuccess, @"SecItemExport error: %ld", (long int)status);
    NSCParameterAssert(data);
    
    return (__bridge_transfer NSData *)data;
}
#endif

static BOOL AFSecKeyIsEqualToKey(SecKeyRef key1, SecKeyRef key2) {
#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
    return [(__bridge id)key1 isEqual:(__bridge id)key2];
#else
    return [AFSecKeyGetData(key1) isEqual:AFSecKeyGetData(key2)];
#endif
}

@implementation AFSecurity
+ (NSArray*)defaultPinnedCertificates{
    static NSArray *_defaultPinnedCertificates = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle *bundle = [NSBundle bundleForClass:[self class]];
        NSArray *paths = [bundle pathsForResourcesOfType:@"cer" inDirectory:@"."];
        
        NSMutableArray *certificates = [NSMutableArray arrayWithCapacity:[paths count]];
        for (NSString *path in paths) {
            NSData *certificateData = [NSData dataWithContentsOfFile:path];
            [certificates addObject:certificateData];
        }
        
        _defaultPinnedCertificates = [[NSArray alloc] initWithArray:certificates];
    });
    
    return _defaultPinnedCertificates;
}


+ (BOOL)shouldTrustServerTrust:(SecTrustRef)serverTrust
               withPinningMode:(AFSSLPinningMode)pinningMode
            pinnedCertificates:(NSArray*)pinnedCertificates
   allowInvalidSSLCertificates:(BOOL)allowInvalidSSLCertificates{
    switch (pinningMode) {
        case AFSSLPinningModePublicKey: {
            NSArray *trustChain = [AFSecurity publicKeyTrustChainForServerTrust:serverTrust];
            NSArray *pinnedPublicKeys = [AFSecurity publicKeysForCertificates:pinnedCertificates];
            return [AFSecurity trustChain:trustChain containsPublicKeyInPinnedPublicKeys:pinnedPublicKeys];
        }
        case AFSSLPinningModeCertificate: {
            NSArray *trustChain = [AFSecurity certificateTrustChainForServerTrust:serverTrust];
            return [AFSecurity trustChain:trustChain containsCertificateInPinnedCertificates:pinnedCertificates];
        }
        case AFSSLPinningModeNone: {
            return (allowInvalidSSLCertificates ||
                    [AFSecurity shouldTrustServerTrust:serverTrust]);
        }
    }
}

#pragma mark - Private Methods

+ (NSArray*)publicKeysForCertificates:(NSArray*)certificates{
    NSMutableArray *publicKeys = [NSMutableArray arrayWithCapacity:[certificates count]];
    
    for (NSData *data in certificates) {
        SecCertificateRef allowedCertificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
        NSParameterAssert(allowedCertificate);
        
        SecCertificateRef allowedCertificates[] = {allowedCertificate};
        CFArrayRef tempCertificates = CFArrayCreate(NULL, (const void **)allowedCertificates, 1, NULL);
        
        SecPolicyRef policy = SecPolicyCreateBasicX509();
        SecTrustRef allowedTrust = NULL;
        OSStatus status = SecTrustCreateWithCertificates(tempCertificates, policy, &allowedTrust);
        NSAssert(status == errSecSuccess, @"SecTrustCreateWithCertificates error: %ld", (long int)status);
        
        SecTrustResultType result = 0;
        status = SecTrustEvaluate(allowedTrust, &result);
        NSAssert(status == errSecSuccess, @"SecTrustEvaluate error: %ld", (long int)status);
        
        SecKeyRef allowedPublicKey = SecTrustCopyPublicKey(allowedTrust);
        NSParameterAssert(allowedPublicKey);
        [publicKeys addObject:(__bridge_transfer id)allowedPublicKey];
        
        CFRelease(allowedTrust);
        CFRelease(policy);
        CFRelease(tempCertificates);
        CFRelease(allowedCertificate);
    }
    
    return [NSArray arrayWithArray:publicKeys];
}

+ (NSArray*)certificateTrustChainForServerTrust:(SecTrustRef)serverTrust{
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:certificateCount];
    
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        [trustChain addObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)];
    }
    return [NSArray arrayWithArray:trustChain];
}

+ (NSArray*)publicKeyTrustChainForServerTrust:(SecTrustRef)serverTrust{
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:certificateCount];
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        
        SecCertificateRef someCertificates[] = {certificate};
        CFArrayRef certificates = CFArrayCreate(NULL, (const void **)someCertificates, 1, NULL);
        
        SecTrustRef trust = NULL;
        
        OSStatus status = SecTrustCreateWithCertificates(certificates, policy, &trust);
        NSAssert(status == errSecSuccess, @"SecTrustCreateWithCertificates error: %ld", (long int)status);
        
        SecTrustResultType result;
        status = SecTrustEvaluate(trust, &result);
        NSAssert(status == errSecSuccess, @"SecTrustEvaluate error: %ld", (long int)status);
        
        [trustChain addObject:(__bridge_transfer id)SecTrustCopyPublicKey(trust)];
        
        CFRelease(trust);
        CFRelease(certificates);
    }
    CFRelease(policy);
    return [NSArray arrayWithArray:trustChain];
}

+ (BOOL)trustChain:(NSArray*)trustChain containsPublicKeyInPinnedPublicKeys:(NSArray*)pinnedPublicKeys{
    for (id publicKey in trustChain) {
        for (id pinnedPublicKey in pinnedPublicKeys) {
            if (AFSecKeyIsEqualToKey((__bridge SecKeyRef)publicKey, (__bridge SecKeyRef)pinnedPublicKey)) {
                return YES;
            }
        }
    }
    return NO;
}

+ (BOOL)trustChain:(NSArray*)trustChain containsCertificateInPinnedCertificates:(NSArray*)pinnedCertificates{
    for (id serverCertificateData in trustChain) {
        if ([pinnedCertificates containsObject:serverCertificateData]) {
            return YES;
        }
    }
    return NO;
}

+ (BOOL)shouldTrustServerTrust:(SecTrustRef)serverTrust{
    SecTrustResultType result = 0;
    OSStatus status = SecTrustEvaluate(serverTrust, &result);
    NSAssert(status == errSecSuccess, @"SecTrustEvaluate error: %ld", (long int)status);
    return (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);
}
@end
