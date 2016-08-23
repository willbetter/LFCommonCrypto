//
//  DKCommonHMAC.h
//  DKSecurity
//
//  Created by wangxiaoxiang on 16/5/27.
//  Copyright © 2016年 wangxiaoxiang. All rights reserved.
//

#import <Foundation/Foundation.h>



typedef NS_ENUM(NSUInteger, LFHmacAlgorithm) {
    LFHmacAlgorithmMD5,
    LFHmacAlgorithmSHA1,
    LFHmacAlgorithmSHA224,
    LFHmacAlgorithmSHA256,
    LFHmacAlgorithmSHA384,
    LFHmacAlgorithmSHA512,
};

@interface LFCommonHMAC : NSObject

+ (NSData/*output data*/ *)hamc:(NSData *)inputData
                            key:(NSData *)key
                      algorithm:(LFHmacAlgorithm)algorithm;

+ (NSData/*output data*/ *)hamc:(NSData *)inputData
                            key:(NSData *)key
                      algorithm:(LFHmacAlgorithm)algorithm
                          error:(NSError *__autoreleasing *)error;
@end
