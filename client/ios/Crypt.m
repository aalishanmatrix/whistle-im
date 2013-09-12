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
 
#import "Crypt.h"
#import "openssl/rsa.h"
#import "openssl/bio.h"
#import "openssl/pem.h"
#import "openssl/rand.h"
#import "openssl/evp.h"
#import "openssl/x509.h"
#import "JFBCrypt.h"

@implementation Crypt

/**
 * Encodes raw data to a base64 encoded string.
 */
+(NSString*)encode64:(NSData*)data {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* out = BIO_new(BIO_s_mem());
    char* enc = NULL;
    @try {
        b64 = BIO_push(b64, out);
        BIO_write(b64, [data bytes], data.length);
        (void) BIO_flush(b64);
        int len = BIO_pending(out);
        enc = calloc(len+1,1);
        BIO_read(out, enc, len);
        // The encoder strictly adds new lines, so...
        return [[NSString stringWithUTF8String:enc] stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    }
    @catch (NSException* ex) {
        return NULL;
    }
    @finally {
        if (out != NULL) BIO_free_all(out);
        if (enc != NULL) free(enc);
    }
}

/**
 * Decodes a base64 encoded string to raw data.
 */
+(NSData*)decode64:(NSString*)s {
    // The decoder requires proper new lines, so...
    NSMutableString* sb = [[NSMutableString alloc] init];
    int i=0, len=[s length];
    while (i <= len-64) {
        [sb appendString:[s substringWithRange:NSMakeRange(i, 64)]];
        [sb appendString:@"\n"];
        i += 64;
    }
    if (len > i) {
        [sb appendString:[s substringWithRange:NSMakeRange(i, len-i)]];
        [sb appendString:@"\n"];
    }
    const char* enc = [sb UTF8String]; // autoreleased
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* out = BIO_new_mem_buf((char*)enc, strlen(enc));
    @try {
        out = BIO_push(b64, out);
        char buf[512]; int n;
        NSMutableData* data = [[NSMutableData alloc] init];
        while ((n = BIO_read(out, buf, 512)) > 0) {
            [data appendBytes:buf length:n];
        }
        return [NSData dataWithData:data];
    }
    @catch (NSException* ex) {
        return NULL;
    }
    @finally {
        if (out != NULL) BIO_free_all(out);
    }
}

/**
 * Converts (multiple) PEM formatted certificates to DER.
 */
+(NSArray*)readPEM:(NSString*)file {
    X509* x = NULL;
    BIO* bio = NULL;
    FILE* fp = NULL;
    NSMutableArray* ret = [NSMutableArray new];
    @try {
        NSRange range = [file rangeOfString:@"/" options:NSBackwardsSearch];
        if (range.location == NSNotFound) {
            NSLog(@"Reading PEM failed: Invalid file name");
            return NULL;
        }
        NSLog(@"Reading PEM: %@", [file substringFromIndex:range.location+1]);
        fp = fopen([file cStringUsingEncoding:NSUTF8StringEncoding], "r");
        while (!feof(fp)) {
            x = X509_new();
            if (PEM_read_X509(fp, &x, NULL, NULL)) {
                char buf[512];
                X509_NAME_oneline(X509_get_subject_name(x), buf, 511);
                NSLog(@"Found certificate: %s", buf);
                bio = BIO_new(BIO_s_mem());
                if (i2d_X509_bio(bio, x)) {
                    int len = BIO_pending(bio);
                    unsigned char data[len];
                    BIO_read(bio, data, len);
                    NSData* cert = [NSData dataWithBytes:data length:len];
                    [ret addObject:cert];
                }
                BIO_free_all(bio); bio = NULL;
            }
            X509_free(x); x = NULL;
        }
        if ([ret count] == 0) {
            NSLog(@"Reading PEM failed: No valid X509 certificates");
            return NULL;
        }
        return [NSArray arrayWithArray:ret];
    }
    @finally {
        if (x != NULL) X509_free(x);
        if (fp != NULL) fclose(fp);
    }
}

/**
 * Checks if a RSA key is generally valid.
 */
+(BOOL)checkkey:(RSA*)key {
    if (key == NULL) return false;
    if (RSA_size(key) != RSA_BYTES) return false; // For now
    return true;
}

/**
 * Generates a private and public key pair.
 */
+(NSArray*)genkeys:(NSNumber*)bits withExp:(NSNumber*)exp ifError:(NSString**)err {
    RSA* rsa = NULL;
    BIO* bio = NULL;
    char* pkey = NULL;
    char* pub = NULL;
    @try {
        // Properly seed
        // RAND_poll();
        int rc = RAND_load_file("/dev/urandom", 32);
        if (rc != 32) {
            *err = @"Seed failed";
            return NULL;
        }
        // Use defaults if not set
        if (bits == NULL) {
            bits = [NSNumber numberWithInt:RSA_BITS];
        }
        if (exp == NULL) {
            exp = [NSNumber numberWithInt:RSA_EXP];
        }
        // Generate
        rsa = RSA_generate_key([bits intValue], [exp intValue], NULL, NULL);
        // Output as PEM
        bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
        int len = BIO_pending(bio);
        pkey = calloc(len+1, 1);
        BIO_read(bio, pkey, len);
        BIO_free_all(bio); bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSA_PUBKEY(bio, rsa);
        len = BIO_pending(bio);
        pub = calloc(len+1, 1);
        BIO_read(bio, pub, len);
        // Return it
        NSMutableArray* ret = [[NSMutableArray alloc] init];
        [ret addObject:[NSString stringWithUTF8String:pkey]];
        [ret addObject:[NSString stringWithUTF8String:pub]];
        *err = NULL;
        return [NSArray arrayWithArray:ret];
    }
    @catch (NSException* ex) {
        *err = [ex reason];
        return NULL;
    }
    @finally {
        if (rsa != NULL) RSA_free(rsa);
        if (bio != NULL) BIO_free_all(bio);
        if (pkey != NULL) free(pkey);
        if (pub != NULL) free(pub);
    }
}

/**
 * Encrypts raw data to base64 with the specified public key and optionally signs it with a private key.
 */
+(NSArray*)encrypt:(NSData*)data withPub:(NSString*)pub withPriv:(NSString*)priv ifError:(NSString**)err {
    RSA* rsaPub = NULL;
    BIO* bio = NULL;
    @try {
        // Parse public key
        const char* pubRaw = [pub UTF8String]; // autoreleased
        bio = BIO_new_mem_buf((char*)pubRaw, strlen(pubRaw));
        rsaPub = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
        if (![Crypt checkkey:rsaPub]) {
            *err = @"Invalid public key";
            return NULL;
        }
        BIO_free_all(bio); bio = NULL;
        
        // Properly seed
        // RAND_poll();
        int rc = RAND_load_file("/dev/urandom", 32);
        if (rc != 32) {
            *err = @"Seed failed";
            return NULL;
        }
        
        // Generate random AES key and IV
        unsigned char key[AES_BYTES], iv[16];
        RAND_bytes(key, AES_BYTES);
        RAND_bytes(iv, 16);
        unsigned char keyIv[AES_BYTES+16];
        memcpy(keyIv, key, AES_BYTES);
        memcpy(keyIv+AES_BYTES, iv, 16);
        
        NSMutableData* encRaw = [[NSMutableData alloc] init];
        
        // Encrypt AES key and IV using RSA-OAEP
        unsigned char buf[RSA_BYTES];
        RSA_public_encrypt(AES_BYTES+16, keyIv, (unsigned char*)&buf, rsaPub, RSA_PKCS1_OAEP_PADDING);
        [encRaw appendBytes:buf length:RSA_BYTES];
        RSA_free(rsaPub); rsaPub = NULL;
        
        // Encrypt data using AES-CBC with PKCS#7 padding (default)
        const EVP_CIPHER* ciph;
        switch (AES_BYTES) {
            case 32:
                ciph = EVP_aes_256_cbc();
                break;
            default:
                *err = @"Invalid aes cipher size";
                return NULL;
        }
        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_EncryptInit(&ctx, ciph, key, iv);
        
        unsigned char aesBuf[[data length]+EVP_MAX_BLOCK_LENGTH];
        int len;
        if (!EVP_EncryptUpdate(&ctx, aesBuf, &len, [data bytes], [data length])) {
            EVP_CIPHER_CTX_cleanup(&ctx);
            *err = @"Cipher update failed";
            return NULL;
        }
        [encRaw appendBytes:aesBuf length:len];
        if (!EVP_EncryptFinal(&ctx, aesBuf, &len)) {
            EVP_CIPHER_CTX_cleanup(&ctx);
            *err = @"Cipher final failed";
            return NULL;
        }
        [encRaw appendBytes:aesBuf length:len];
        EVP_CIPHER_CTX_cleanup(&ctx);
        
        // Sign
        NSString* sig = NULL;
        if (priv != NULL) {
            sig = [self sign:encRaw withPriv:priv ifError:err];
        }
        
        // Return it
        NSString* encStr = [self encode64:encRaw];
        *err = NULL;
        return [NSArray arrayWithObjects:encStr, sig != NULL ? sig : [NSNull null], nil];
    }
    @catch (NSException *ex) {
        *err = [ex reason];
        return NULL;
    }
    @finally {
        if (bio != NULL) BIO_free_all(bio);
        if (rsaPub != NULL) RSA_free(rsaPub);
    }
}

/**
 * Signs raw data with the specified private key.
 */
+(NSString*)sign:(NSData*) data withPriv:(NSString*)priv ifError:(NSString**)err {
    BIO* bio = NULL;
    RSA* rsaPkey = NULL;
    EVP_PKEY* pkey = NULL;
    @try {
        const char* privRaw = [priv UTF8String]; // autoreleased
        bio = BIO_new_mem_buf((char*)privRaw, strlen(privRaw));
        rsaPkey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        if (![Crypt checkkey:rsaPkey]) {
            *err = @"Invalid private key";
            return NULL;
        }
        BIO_free_all(bio); bio = NULL;
        EVP_MD_CTX md;
        pkey = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pkey, rsaPkey);
        EVP_MD_CTX_init(&md);
        EVP_DigestSignInit(&md, NULL, EVP_sha1(), NULL, pkey);
        if (!EVP_DigestSignUpdate(&md, [data bytes], [data length])) {
            EVP_MD_CTX_cleanup(&md);
            *err = @"Sign update failed";
            return NULL;
        }
        unsigned char sigRaw[EVP_PKEY_size(pkey)];
        size_t sigLen;
        if (!EVP_DigestSignFinal(&md, sigRaw, &sigLen)) {
            EVP_MD_CTX_cleanup(&md);
            *err = @"Sign final failed";
            return NULL;
        }
        EVP_MD_CTX_cleanup(&md);
        NSData* sig = [NSData dataWithBytes:sigRaw length:sigLen];
        *err = NULL;
        return [self encode64:sig];
    }
    @catch (NSException* ex) {
        *err = [ex reason];
        return NULL;
    }
    @finally {
        if (bio != NULL) BIO_free_all(bio);
        if (rsaPkey != NULL) RSA_free(rsaPkey);
        if (pkey != NULL) EVP_PKEY_free(pkey);
    }
}

/**
 * Decrypts base64 encoded data to raw data with the specified private key and optionaly verifies the signature with a public key.
 */
+(NSArray*)decrypt:(NSString*)enc withSig:(NSString*)sig withPriv:(NSString*)priv withPub:(NSString*)pub ifError:(NSString**)err {
    RSA* rsaPriv = NULL;
    BIO* bio = NULL;
    @try {
        // Parse private key
        const char* privRaw = [priv UTF8String]; // autoreleased
        bio = BIO_new_mem_buf((char*)privRaw, strlen(privRaw));
        rsaPriv = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        BIO_free_all(bio); bio = NULL;
        int keySize = RSA_size(rsaPriv);
        if (![Crypt checkkey:rsaPriv]) {
            *err = @"Invalid rsa key";
            return NULL;
        }
        
        NSData* encRaw = [Crypt decode64:enc];
        
        // Decrypt RSA-OAEP part
        unsigned char keyIv[keySize];
        int len = RSA_private_decrypt(keySize, [encRaw bytes], keyIv, rsaPriv, RSA_PKCS1_OAEP_PADDING);
        if (len < 32+16) { // Minimum AES-256 key+IV
            *err = @"Invalid rsa data";
            return NULL;
        }
        
        NSMutableData* dec = [[NSMutableData alloc] init];
        
        // Decrypt data with AES-CBC using PKCS#7 padding (default)
        const EVP_CIPHER* ciph;
        switch (len-16) {
            case 32:
                ciph = EVP_aes_256_cbc();
                break;
            default:
                *err = @"Invalid aes cipher size";
                return NULL;
        }
        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_DecryptInit(&ctx, ciph, keyIv, keyIv+AES_BYTES);
        
        unsigned char buf[[encRaw length]-RSA_BYTES+EVP_MAX_BLOCK_LENGTH]; // AES portion size plus tolerace
        if (!EVP_DecryptUpdate(&ctx, buf, &len, [encRaw bytes]+RSA_BYTES, [encRaw length]-RSA_BYTES)) {
            EVP_CIPHER_CTX_cleanup(&ctx);
            *err = @"Cipher update failed";
            return NULL;
        }
        [dec appendBytes:buf length:len];
        if (!EVP_DecryptFinal(&ctx, buf, &len)) {
            EVP_CIPHER_CTX_cleanup(&ctx);
            *err = @"Cipher final failed";
            return NULL;
        }
        [dec appendBytes:buf length:len];
        EVP_CIPHER_CTX_cleanup(&ctx);
        
        // Verify
        NSNumber* ver = NULL;
        if (sig != NULL && pub != NULL) {
            ver = [self verify:encRaw withSig:sig withPub:pub ifError:err];
        }
        
        // Return it
        *err = NULL;
        return [NSArray arrayWithObjects:[NSData dataWithData:dec], ver != NULL ? ver : [NSNull null], nil];
    }
    @catch (NSException* ex) {
        *err = [ex reason];
        return NULL;
    }
    @finally {
        if (rsaPriv != NULL) RSA_free(rsaPriv);
        if (bio != NULL) BIO_free_all(bio);
    }
}

/**
 * Verifies a signature against raw data with the specified public key.
 */
+(NSNumber*)verify:(NSData*) data withSig:(NSString*)sig withPub:(NSString*)pub ifError:(NSString**)err {
    RSA* rsaKey = NULL;
    BIO* bio = NULL;
    EVP_PKEY* key = NULL;
    @try {
        const char* pubRaw = [pub UTF8String]; // autoreleased
        NSData* sigRaw = [Crypt decode64:sig]; // "
        BIO* bio = BIO_new_mem_buf((char*)pubRaw, strlen(pubRaw));
        rsaKey = PEM_read_bio_RSA_PUBKEY(bio, &rsaKey, NULL, NULL);
        if (![Crypt checkkey:rsaKey]) {
            *err = @"Invalid public key";
            return NULL;
        }
        key = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(key, rsaKey);
        EVP_MD_CTX md;
        EVP_MD_CTX_init(&md);
        EVP_DigestVerifyInit(&md, NULL, EVP_sha1(), NULL, key);
        EVP_DigestVerifyUpdate(&md, [data bytes], [data length]);
        int ret = EVP_DigestVerifyFinal(&md, (unsigned char*)[sigRaw bytes], [sigRaw length]);
        EVP_MD_CTX_cleanup(&md);
        *err = NULL;
        return [NSNumber numberWithBool:ret == 1 ? YES : NO];
    }
    @catch (NSException* ex) {
        *err = [ex reason];
        return [NSNumber numberWithBool:NO];
    }
    @finally {
        if (bio != NULL) BIO_free_all(bio);
        if (rsaKey != NULL) RSA_free(rsaKey);
        if (key != NULL) EVP_PKEY_free(key);
    }
}

/**
 * Hashes a password through bcrypt.
 */
+(NSString*)hash:(NSString*)pass withSaltOrRounds:(NSObject*)saltOrRounds {
    NSString* salt;
    if ([saltOrRounds isKindOfClass:[NSNumber class]]) {
        salt = [JFBCrypt generateSaltWithNumberOfRounds:(NSInteger)saltOrRounds];
    } else {
        salt = (NSString*)saltOrRounds;
    }
    return [JFBCrypt hashPassword:pass withSalt:salt];
}

@end
