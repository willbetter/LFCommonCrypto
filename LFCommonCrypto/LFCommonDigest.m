//
//  DKCommonDigest.m
//  DKSecurity
//
//  Created by wangxiaoxiang on 16/5/27.
//  Copyright © 2016年 wangxiaoxiang. All rights reserved.
//

#import "LFCommonDigest.h"
#import <CommonCrypto/CommonDigest.h>
@implementation LFCommonDigest


+ (NSData *) MD2:(NSData *)inputData {
    unsigned char hash[CC_MD2_DIGEST_LENGTH];
    (void) CC_MD2( [inputData bytes], (CC_LONG)[inputData length], hash );
    return ( [NSData dataWithBytes: hash length: CC_MD2_DIGEST_LENGTH] );
}

+ (NSData *) MD4:(NSData *)inputData {
    unsigned char hash[CC_MD4_DIGEST_LENGTH];
    (void) CC_MD4( [inputData bytes], (CC_LONG)[inputData length], hash );
    return ( [NSData dataWithBytes: hash length: CC_MD4_DIGEST_LENGTH] );
}

+ (NSData *) MD5:(NSData *)inputData {
    unsigned char hash[CC_MD5_DIGEST_LENGTH];
    (void) CC_MD5( [inputData bytes], (CC_LONG)[inputData length], hash );
    return ( [NSData dataWithBytes: hash length: CC_MD5_DIGEST_LENGTH] );
}

+ (NSData *) SHA1:(NSData *)inputData {
    unsigned char hash[CC_SHA1_DIGEST_LENGTH];
    (void) CC_SHA1( [inputData bytes], (CC_LONG)[inputData length], hash );
    return ( [NSData dataWithBytes: hash length: CC_SHA1_DIGEST_LENGTH] );
}

+ (NSData *) SHA224:(NSData *)inputData {
    unsigned char hash[CC_SHA224_DIGEST_LENGTH];
    (void) CC_SHA224( [inputData bytes], (CC_LONG)[inputData length], hash );
    return ( [NSData dataWithBytes: hash length: CC_SHA224_DIGEST_LENGTH] );
}

+ (NSData *) SHA256:(NSData *)inputData {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    (void) CC_SHA256( [inputData bytes], (CC_LONG)[inputData length], hash );
    return ( [NSData dataWithBytes: hash length: CC_SHA256_DIGEST_LENGTH] );
}
+ (NSData *) SHA384:(NSData *)inputData {
    unsigned char hash[CC_SHA384_DIGEST_LENGTH];
    (void) CC_SHA384( [inputData bytes], (CC_LONG)[inputData length], hash );
    return ( [NSData dataWithBytes: hash length: CC_SHA384_DIGEST_LENGTH] );
}
+ (NSData *) SHA512:(NSData *)inputData {
    unsigned char hash[CC_SHA512_DIGEST_LENGTH];
    (void) CC_SHA512( [inputData bytes], (CC_LONG)[inputData length], hash );
    return ( [NSData dataWithBytes: hash length: CC_SHA512_DIGEST_LENGTH] );
}

@end
