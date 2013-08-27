//
//  whistle.im native iOS crypt.
//  Daniel Wirtz <dcode@dcode.io>
//  All rights reserved.
//

#import <Foundation/Foundation.h>

static int const RSA_BITS = 2048;
static int const RSA_BYTES = RSA_BITS/8;
static int const RSA_EXP = 0x10001;
static int const AES_BITS = 256;
static int const AES_BYTES = AES_BITS/8;

@interface Crypt : NSObject

// Utility
+(NSString*)encode64:(NSData*)data;
+(NSData*)decode64:(NSString*)s;

// Actual crypt
+(NSArray*)genkeys:(NSNumber*)bits withExp:(NSNumber*)exp ifError:(NSString**)err;
+(NSArray*)encrypt:(NSData*)data withPub:(NSString*)pub withPriv:(NSString*)priv ifError:(NSString**)err;
+(NSArray*)decrypt:(NSString*)enc withSig:(NSString*)sig withPriv:(NSString*)priv withPub:(NSString*)pub ifError:(NSString**)err;
+(NSString*)hash:(NSString*)pass withSaltOrRounds:(NSObject*)saltOrRounds;

@end
