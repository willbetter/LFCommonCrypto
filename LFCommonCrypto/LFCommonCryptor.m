//
//  DKCommonCrypto.m
//  DKSecurity
//
//  Created by wangxiaoxiang on 16/5/27.
//  Copyright © 2016年 wangxiaoxiang. All rights reserved.
//

#import "LFCommonCryptor.h"
#import <CommonCrypto/CommonCryptor.h>

static NSString * const DKCommonCryptoErrorDomain = @"com.dk_common_crypto.error_domain";


FOUNDATION_STATIC_INLINE void DKCommonCryptoFixKeyLengths( CCAlgorithm algorithm, NSMutableData * keyData, NSMutableData * ivData ) {
    NSUInteger keyLength = [keyData length];
    switch ( algorithm ) {
        case kCCAlgorithmAES128: {
            if ( keyLength < 16 ) {
                [keyData setLength: 16];
            }
            else if ( keyLength < 24 ) {
                [keyData setLength: 24];
            }
            else {
                [keyData setLength: 32];
            }
            
            break;
        }
        case kCCAlgorithmDES: {
            [keyData setLength: 8];
            break;
        }
        case kCCAlgorithm3DES: {
            [keyData setLength: 24];
            break;
        }
        case kCCAlgorithmCAST: {
            if ( keyLength < 5 ) {
                [keyData setLength: 5];
            } else if ( keyLength > 16 ) {
                [keyData setLength: 16];
            }
            
            break;
        }
        case kCCAlgorithmRC4:{
            if ( keyLength > 512 )
                [keyData setLength: 512];
            break;
        }
            
        default:
            break;
    }
    
    [ivData setLength: [keyData length]];
}

@implementation LFCommonCryptor

#pragma mark - AES256 crypt

+ (NSData *)AES256Encrypt:(NSData *)inputData key:(NSData *)key error:(NSError *__autoreleasing *)error {
    return [self AES256Encrypt:inputData key:key initializationVector:nil error:error];
}

+ (NSData *)AES256Decrypt:(NSData *)inputData key:(NSData *)key error:(NSError *__autoreleasing *)error {
    return [self AES256Decrypt:inputData key:key initializationVector:nil error:error];
}

+ (NSData *)AES256Encrypt:(NSData *)inputData key: (NSData *) key initializationVector:(NSData *)initializationVector error: (NSError **) error {
    if (inputData == nil) return nil;
    
    CCCryptorStatus status = kCCSuccess;
    
    NSData *outputData = nil;
    outputData = [self encrypt:inputData algorithm:kCCAlgorithmAES128 key:key initializationVector:initializationVector options:kCCOptionPKCS7Padding error:&status];
    
    if (status != kCCSuccess && error != NULL) {
        *error = [self errorWithCCCryptorStatus:status];
    }
    
    return outputData;
}

+ (NSData *)AES256Decrypt:(NSData *)inputData key: (NSData *) key initializationVector:(NSData *)initializationVector error: (NSError **) error {
    if (inputData == nil) return nil;
    
    CCCryptorStatus status = kCCSuccess;
    
    NSData *outputData = nil;
    outputData = [self decrypt:inputData algorithm:kCCAlgorithmAES128 key:key initializationVector:initializationVector options:kCCOptionPKCS7Padding error:&status];
    
    if (status != kCCSuccess && error != NULL) {
        *error = [self errorWithCCCryptorStatus:status];
    }
    
    return outputData;
}

#pragma mark - DES crypt

+ (NSData *)DESEncrypt:(NSData *)inputData key: (NSData *) key error: (NSError **) error {
    CCCryptorStatus status = kCCSuccess;
    NSData *outputData = nil;
    outputData = [self encrypt:inputData
                     algorithm:kCCAlgorithmDES
                           key:key
                       options:kCCOptionPKCS7Padding
                         error:&status];
    
    if (status != kCCSuccess && error != NULL) {
        *error = [self errorWithCCCryptorStatus:status];
    }
    return outputData;
    
}
+ (NSData *)DESDecrypt:(NSData *)inputData key: (NSData *) key error: (NSError **) error {
    CCCryptorStatus status = kCCSuccess;
    NSData *outputData = nil;
    outputData = [self decrypt:inputData
                     algorithm:kCCAlgorithmDES
                           key:key
                       options:kCCOptionPKCS7Padding
                         error:&status];
    
    if (status != kCCSuccess && error != NULL) {
        *error = [self errorWithCCCryptorStatus:status];
    }
    return outputData;
}

#pragma mark - CAST crypt

+ (NSData *) CASTEncrypt:(NSData *)inputData key: (NSData *) key error: (NSError **) error {
    CCCryptorStatus status = kCCSuccess;
    NSData *outputData = nil;
    outputData = [self encrypt:inputData
                     algorithm:kCCAlgorithmCAST
                           key:key
                       options:kCCOptionPKCS7Padding
                         error:&status];
    
    if (status != kCCSuccess && error != NULL) {
        *error = [self errorWithCCCryptorStatus:status];
    }
    return outputData;
}

+ (NSData *) CASTDecrypt:(NSData *)inputData key: (NSData *) key error: (NSError **) error {
    CCCryptorStatus status = kCCSuccess;
    NSData *outputData = nil;
    outputData = [self decrypt:inputData
                     algorithm:kCCAlgorithmCAST
                           key:key
                       options:kCCOptionPKCS7Padding
                         error:&status];
    
    if (status != kCCSuccess && error != NULL) {
        *error = [self errorWithCCCryptorStatus:status];
    }
    return outputData;
}


#pragma mark - encrypt
+ (NSData *)encrypt:(NSData *)inputData
          algorithm:(CCAlgorithm)algorithm
                key:(NSData *)key
              error:(CCCryptorStatus *)error {
    return [self encrypt:inputData
               algorithm:algorithm
                     key:key
    initializationVector:nil
                 options:0
                   error:error];
}

+ (NSData *)encrypt:(NSData *)inputData
          algorithm:(CCAlgorithm)algorithm
                key:(NSData *)key
            options:(CCOptions)options
              error:(CCCryptorStatus *)error{
    return [self encrypt:inputData
               algorithm:algorithm
                     key:key
    initializationVector:nil
                 options:options
                   error:error];
}

+ (NSData *) encrypt:(NSData *)inputData
           algorithm:(CCAlgorithm)algorithm
                 key:(NSData *)key
initializationVector:(NSData *)initializationVector
             options:(CCOptions)options
               error:(CCCryptorStatus *)error {
    
    if (inputData == nil) return nil;
    
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = kCCSuccess;
    
    NSParameterAssert([key isKindOfClass: [NSData class]]);
    NSParameterAssert(initializationVector == nil || [initializationVector isKindOfClass: [NSData class]]);
    
    NSMutableData * keyData, * ivData;
    keyData = (NSMutableData *) [key mutableCopy];
    ivData = (NSMutableData *) [initializationVector mutableCopy];

    
    // ensure correct lengths for key and iv data, based on algorithms
    DKCommonCryptoFixKeyLengths( algorithm, keyData, ivData );
    
    status = CCCryptorCreate( kCCEncrypt,
                             algorithm,
                             options,
                             [keyData bytes], [keyData length], [ivData bytes],
                             &cryptor );
    
    if ( status != kCCSuccess )
    {
        if ( error != NULL )
            *error = status;
        return ( nil );
    }
    
    NSData * result = [self _runCryptor: cryptor data:inputData result: &status];
    if ( (result == nil) && (error != NULL) )
        *error = status;
    
    CCCryptorRelease( cryptor );
    
    return result;
}

#pragma mark - decrypt

+ (NSData *)decrypt:(NSData *)inputData algorithm:(CCAlgorithm)algorithm key:(NSData *)key error:(CCCryptorStatus *)error {
    return [self decrypt:inputData algorithm:algorithm key:key initializationVector:nil options:0 error:error];
}

+ (NSData *)decrypt:(NSData *)inputData algorithm:(CCAlgorithm)algorithm key:(NSData *)key options:(CCOptions)options error:(CCCryptorStatus *)error {
    return [self decrypt:inputData algorithm:algorithm key:key initializationVector:nil options:options error:error];
}

+ (NSData *)decrypt:(NSData *)inputData
          algorithm:(CCAlgorithm) algorithm
                key:(NSData *)key
initializationVector:(NSData *)initializationVector
            options:(CCOptions)options
              error:(CCCryptorStatus *)error {
    
    if (inputData == nil) return nil;
    
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = kCCSuccess;
    
    NSParameterAssert([key isKindOfClass: [NSData class]] );
    NSParameterAssert(initializationVector == nil || [initializationVector isKindOfClass: [NSData class]] );
    
    NSMutableData * keyData, * ivData;
    keyData = (NSMutableData *) [key mutableCopy];
    ivData = (NSMutableData *) [initializationVector mutableCopy];	// data or nil
    

    
    // ensure correct lengths for key and iv data, based on algorithms
    DKCommonCryptoFixKeyLengths( algorithm, keyData, ivData );
    
    status = CCCryptorCreate( kCCDecrypt, algorithm, options,
                             [keyData bytes], [keyData length], [ivData bytes],
                             &cryptor );
    
    if ( status != kCCSuccess )
    {
        if ( error != NULL )
            *error = status;
        return ( nil );
    }
    
    NSData * result = [self _runCryptor: cryptor data:inputData result: &status];
    if ( (result == nil) && (error != NULL) )
        *error = status;
    
    CCCryptorRelease( cryptor );
    
    return result;
}

#pragma mark - private

+ (NSError *) errorWithCCCryptorStatus: (CCCryptorStatus) status
{
    NSString * description = nil, * reason = nil;
    
    switch ( status )
    {
        case kCCSuccess:
            description = NSLocalizedString(@"Success", @"Error description");
            break;
            
        case kCCParamError:
            description = NSLocalizedString(@"Parameter Error", @"Error description");
            reason = NSLocalizedString(@"Illegal parameter supplied to encryption/decryption algorithm", @"Error reason");
            break;
            
        case kCCBufferTooSmall:
            description = NSLocalizedString(@"Buffer Too Small", @"Error description");
            reason = NSLocalizedString(@"Insufficient buffer provided for specified operation", @"Error reason");
            break;
            
        case kCCMemoryFailure:
            description = NSLocalizedString(@"Memory Failure", @"Error description");
            reason = NSLocalizedString(@"Failed to allocate memory", @"Error reason");
            break;
            
        case kCCAlignmentError:
            description = NSLocalizedString(@"Alignment Error", @"Error description");
            reason = NSLocalizedString(@"Input size to encryption algorithm was not aligned correctly", @"Error reason");
            break;
            
        case kCCDecodeError:
            description = NSLocalizedString(@"Decode Error", @"Error description");
            reason = NSLocalizedString(@"Input data did not decode or decrypt correctly", @"Error reason");
            break;
            
        case kCCUnimplemented:
            description = NSLocalizedString(@"Unimplemented Function", @"Error description");
            reason = NSLocalizedString(@"Function not implemented for the current algorithm", @"Error reason");
            break;
            
        default:
            description = NSLocalizedString(@"Unknown Error", @"Error description");
            break;
    }
    
    NSMutableDictionary * userInfo = [[NSMutableDictionary alloc] init];
    [userInfo setObject: description forKey: NSLocalizedDescriptionKey];
    
    if ( reason != nil )
        [userInfo setObject: reason forKey: NSLocalizedFailureReasonErrorKey];
    
    NSError * result = [NSError errorWithDomain: DKCommonCryptoErrorDomain code: status userInfo: userInfo];
    
    return ( result );
}

+ (NSData *) _runCryptor: (CCCryptorRef) cryptor data:(NSData *)inputData result: (CCCryptorStatus *) status
{
    size_t bufsize = CCCryptorGetOutputLength( cryptor, (size_t)[inputData length], true );
    void * buf = malloc( bufsize );
    size_t bufused = 0;
    size_t bytesTotal = 0;
    *status = CCCryptorUpdate( cryptor, [inputData bytes], (size_t)[inputData length],
                              buf, bufsize, &bufused );
    if ( *status != kCCSuccess )
    {
        free( buf );
        return ( nil );
    }
    
    bytesTotal += bufused;
    
    // From Brent Royal-Gordon (Twitter: architechies):
    //  Need to update buf ptr past used bytes when calling CCCryptorFinal()
    *status = CCCryptorFinal( cryptor, buf + bufused, bufsize - bufused, &bufused );
    if ( *status != kCCSuccess )
    {
        free( buf );
        return ( nil );
    }
    
    bytesTotal += bufused;
    
    return ( [NSData dataWithBytesNoCopy: buf length: bytesTotal] );
}

@end
