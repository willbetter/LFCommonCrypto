//
//  DKCommonHMAC.m
//  DKSecurity
//
//  Created by wangxiaoxiang on 16/5/27.
//  Copyright © 2016年 wangxiaoxiang. All rights reserved.
//

#import "LFCommonHMAC.h"
#import <CommonCrypto/CommonHMAC.h>
FOUNDATION_STATIC_INLINE CC_LONG LFCommonHMACLength(CCHmacAlgorithm algorithm) {
    
    CC_LONG length = -1;
    switch (algorithm) {
        case kCCHmacAlgSHA1:
            length = CC_SHA1_DIGEST_LENGTH;
            break;
        case kCCHmacAlgSHA224:
            length = CC_SHA224_DIGEST_LENGTH;
            break;
        case kCCHmacAlgSHA256:
            length = CC_SHA256_DIGEST_LENGTH;
            break;
        case kCCHmacAlgSHA384:
            length = CC_SHA384_DIGEST_LENGTH;
            break;
        case kCCHmacAlgSHA512:
            length = CC_SHA512_DIGEST_LENGTH;
            break;
        case kCCHmacAlgMD5:
            length = CC_MD5_DIGEST_LENGTH;
            break;
        default:
            break;
    }
    return length;
}


FOUNDATION_STATIC_INLINE CCHmacAlgorithm transformHmacAlgorithm(LFHmacAlgorithm algorithm){
    
    CCHmacAlgorithm  cchmacAlgorithm;
    switch (algorithm) {
        case LFHmacAlgorithmMD5:
            cchmacAlgorithm = kCCHmacAlgMD5;
            break;
        case LFHmacAlgorithmSHA1:
            cchmacAlgorithm = kCCHmacAlgSHA1;
            break;
        case LFHmacAlgorithmSHA224:
            cchmacAlgorithm = kCCHmacAlgSHA224;
            break;
        case LFHmacAlgorithmSHA256:
            cchmacAlgorithm = kCCHmacAlgSHA256;
            break;
        case LFHmacAlgorithmSHA384:
            cchmacAlgorithm = kCCHmacAlgSHA384;
            break;
        case LFHmacAlgorithmSHA512:
            cchmacAlgorithm = kCCHmacAlgSHA512;
            break;
        default:
            break;
    }
    return cchmacAlgorithm;
}



@implementation LFCommonHMAC
+ (NSData *)hamc:(NSData *)inputData key:(NSData *)key algorithm:(LFHmacAlgorithm)algorithm {
    return [self hamc:inputData key:key algorithm:transformHmacAlgorithm(algorithm) error:nil];
}

+ (NSData *)hamc:(NSData *)inputData key:(NSData *)key algorithm:(LFHmacAlgorithm)algorithm error:(NSError *__autoreleasing *)error {
    //确认长度
    CCHmacAlgorithm hmaAlgorithm = transformHmacAlgorithm(algorithm);
    CC_LONG length = LFCommonHMACLength(hmaAlgorithm);
    if (length == -1) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:@"com.youku.common_crypto" code:-1 userInfo:@{NSLocalizedDescriptionKey:@"algorithm err"}];
            return nil;
        }
    }
    
    unsigned char *digest;
    digest = malloc(length);
    
    CCHmac(hmaAlgorithm, key.bytes, key.length, inputData.bytes, inputData.length, digest);
    
    NSData *digestData = [NSData dataWithBytes:digest length:length];
    free(digest);
    return digestData;
}
@end
