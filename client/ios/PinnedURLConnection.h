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

@interface PinnedURLConnection : NSObject

@property (nonatomic) BOOL _finishedLoading;
@property (nonatomic) NSMutableData* _receivedData;
@property (nonatomic) NSError* _error;
@property (nonatomic) NSURLResponse* _response;

+ (NSData*)sendSynchronousRequest:(NSURLRequest *)request returningResponse:(NSURLResponse**)response error:(NSError**)error;

@end
