//
//  DKCommonDigest.h
//  DKSecurity
//
//  Created by wangxiaoxiang on 16/5/27.
//  Copyright © 2016年 wangxiaoxiang. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface LFCommonDigest : NSObject


+ (NSData/*output data*/ *)MD2:(NSData *)inputData;
+ (NSData/*output data*/ *)MD4:(NSData *)inputData;
+ (NSData/*output data*/ *)MD5:(NSData *)inputData;

+ (NSData/*output data*/ *)SHA1:(NSData *)inputData;
+ (NSData/*output data*/ *)SHA224:(NSData *)inputData;
+ (NSData/*output data*/ *)SHA256:(NSData *)inputData;
+ (NSData/*output data*/ *)SHA384:(NSData *)inputData;
+ (NSData/*output data*/ *)SHA512:(NSData *)inputData;

@end
