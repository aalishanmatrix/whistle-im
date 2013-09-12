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
 
#import "PinnedURLConnection.h"
#import "Crypt.h"

@implementation PinnedURLConnection

@synthesize _finishedLoading;
@synthesize _receivedData;
@synthesize _error;
@synthesize _response;

static NSArray* ca = NULL;
static NSArray* cert = NULL;
static NSRegularExpression* expr = NULL;
/**
 * Synchronously performs an HTTPS request with certificate pinning.
 */
+ (NSData*)sendSynchronousRequest:(NSURLRequest *)request returningResponse:(NSURLResponse**)response error:(NSError**)error {
    if (cert == NULL) {
        ca = [Crypt readPEM:[[NSBundle mainBundle] pathForResource:@"ca" ofType:@"pem"]];
        cert = [Crypt readPEM:[[NSBundle mainBundle] pathForResource:@"cert" ofType:@"pem"]];
        expr = [NSRegularExpression regularExpressionWithPattern:@"^([a-zA-Z0-9\\-]+\\.)*whistle\\.im$" options:0 error:NULL];
    }
    if (cert == NULL) {
        NSLog(@"Failed to load server cerficiate: NULL");
        *error = [NSError errorWithDomain:@"im.whistle" code:0 userInfo:NULL];
        return NULL;
    }
    PinnedURLConnection* inst = [PinnedURLConnection new];
    inst._finishedLoading = NO;
    inst._receivedData = [[NSMutableData alloc] init];
    inst._error = NULL;
    inst._response = NULL;
    NSURLConnection* con = [NSURLConnection connectionWithRequest:request delegate:inst];
    [con start];
    CFRunLoopRun();
    *error = inst._error;
    *response = inst._response;
    return inst._receivedData;
}

- (BOOL)connection:(NSURLConnection*)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace*)protectionSpace {
    if (![protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSLog(@"Request failed: Invalid authentication method: %@", protectionSpace.authenticationMethod);
        return false;
    }
    NSString* host = [protectionSpace host];
    if ([expr numberOfMatchesInString:host options:0 range:NSMakeRange(0, [host length])] != 1) {
        NSLog(@"Request failed: Invalid host: %@", host);
        return false;
    }
    return true;
}

- (void)connection:(NSURLConnection*)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge*)challenge {
    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString: NSURLAuthenticationMethodServerTrust]) {
        NSString* host = [[challenge protectionSpace] host];
        do {
            if ([expr numberOfMatchesInString:host options:0 range:NSMakeRange(0, [host length])] != 1) { // Be sure
                NSLog(@"Request failed: Invalid host: %@", host);
                break; // failed
            }
    
            SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
            if(nil == serverTrust) {
                NSLog(@"Request failed: Server trust is NULL");
                break; // failed
            }
            
            OSStatus status = SecTrustEvaluate(serverTrust, NULL);
            if(!(errSecSuccess == status)) {
                NSLog(@"Requst failed: Failed to evaluate server trust");
                break; // failed
            }
            
            SecCertificateRef serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
            if(nil == serverCertificate) {
                NSLog(@"Request failed: Missing server certificate");
                break; // failed
            }
            
            CFDataRef serverCertificateData = SecCertificateCopyData(serverCertificate);
            if(nil == serverCertificateData) {
                NSLog(@"Request failed: Failed to copy server certificate");
                break; // failed
            }
            
            const UInt8* const data = CFDataGetBytePtr(serverCertificateData);
            const CFIndex size = CFDataGetLength(serverCertificateData);
            NSData* cert1 = [NSData dataWithBytes:data length:(NSUInteger)size];
            if (cert1 == nil) {
                NSLog(@"Request failed: Failed to process server certificate");
                break; // failed
            }
            
            BOOL valid = false;
            for (int i=0; i<[cert count]; i++) {
                NSData* cert2 = [cert objectAtIndex:i];
                if ([cert1 isEqualToData:cert2]) {
                    valid = true;
                    break;
                }
            }
            if (!valid) {
                NSLog(@"Request failed: Invalid server certificate");
                break; // failed
            }
            
            return [[challenge sender] useCredential: [NSURLCredential credentialForTrust: serverTrust] forAuthenticationChallenge: challenge];
        } while(0);
        return [[challenge sender] cancelAuthenticationChallenge: challenge];
    }
}
    
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    _response=response;
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    [_receivedData appendData:data];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    _error=error;
    CFRunLoopStop(CFRunLoopGetCurrent());
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    CFRunLoopStop(CFRunLoopGetCurrent());
}

@end
