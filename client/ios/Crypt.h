/*
 whistle.im iOS cryptography library
 Copyright (C) 2013 Daniel Wirtz - http://dcode.io
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
 
#import <Foundation/Foundation.h>

static int const RSA_BITS   = 2048;         // Default RSA key size in bits
static int const RSA_BYTES  = RSA_BITS/8;   // Default RSA key size in bytes
static int const RSA_EXP    = 0x10001;      // Public RSA exponent, 65537
static int const AES_BITS   = 256;          // Default AES key size in bits
static int const AES_BYTES  = AES_BITS/8;   // Default AES key size in bytes

@interface Crypt : NSObject

// Utility
+(NSString*)encode64:(NSData*)data;
+(NSData*)decode64:(NSString*)s;
+(NSArray*)readPEM:(NSString*)file;

// Crypt
+(NSArray*)genkeys:(NSNumber*)bits withExp:(NSNumber*)exp ifError:(NSString**)err;
+(NSArray*)encrypt:(NSData*)data withPub:(NSString*)pub withPriv:(NSString*)priv ifError:(NSString**)err;
+(NSString*)sign:(NSData*) data withPriv:(NSString*)priv ifError:(NSString**)err;
+(NSArray*)decrypt:(NSString*)enc withSig:(NSString*)sig withPriv:(NSString*)priv withPub:(NSString*)pub ifError:(NSString**)err;
+(NSNumber*)verify:(NSData*) data withSig:(NSString*)sig withPub:(NSString*)pub ifError:(NSString**)err;
+(NSString*)hash:(NSString*)pass withSaltOrRounds:(NSObject*)saltOrRounds;

@end
