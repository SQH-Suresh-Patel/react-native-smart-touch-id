#import "RCTTouchId.h"
#import <React/RCTUtils.h>
#import <LocalAuthentication/LocalAuthentication.h>

@implementation RCTTouchId

RCT_EXPORT_MODULE(TouchId);

RCT_EXPORT_METHOD(verify:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSString *description;
    NSString *title;

    if(options != nil) {
        NSArray *keys = [options allKeys];

        if([keys containsObject:@"description"]) {
            description = [options objectForKey:@"description"];
        }
        if([keys containsObject:@"title"]) {
            title = [options objectForKey:@"title"];
        }
    }

    if(description != nil) {
        LAContext *context = [[LAContext alloc] init];
        context.localizedFallbackTitle = title;
        NSError *error;
        // TouchID is supported
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
            [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                    localizedReason:description
                              reply:^(BOOL success, NSError *error) {
                                  //Authenticate failed
                                  if(error) {
                                      reject([NSString stringWithFormat:@"%ld", error.code], @"", nil);
                                  }
                                  else {
                                      resolve(@[[NSNull null]]);
                                  }
                              }];
        }
        // TouchID is not supported
        else {
            reject(@"", @"", nil);
        }
    }
}

RCT_EXPORT_METHOD(isSupported:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    LAContext *context = [[LAContext alloc] init];
    NSError *error;
    // TouchID is supported
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        resolve(@[[NSNull null]]);
    }
    else {
        // TouchID is not supported
        reject(@"", @"", nil);
    }
}

RCT_EXPORT_METHOD(isFingerPrintChanged:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject){
    if ([self hasFingerPrintChanged]) {
        // TouchID is changed
        resolve(@[[NSNull null]]);
    }else{
        // TouchID is not change
        reject(@"", @"", nil);
    }
}
-(BOOL)hasFingerPrintChanged{
    
    BOOL changed = NO;
    
    LAContext *context = [[LAContext alloc] init];
    [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil];
    
    NSData *domainState = [context evaluatedPolicyDomainState];
    
    // load the last domain state from touch id
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSData *oldDomainState = [defaults objectForKey:@"domainTouchID"];
    
    if (oldDomainState)
    {
        // check for domain state changes
        
        if ([oldDomainState isEqual:domainState])
        {
            NSLog(@"nothing changed.");
        }
        else
        {
            changed = YES;
            NSLog(@"domain state was changed!");
            
        }
        
    }
    // save the domain state that will be loaded next time
    [defaults setObject:domainState forKey:@"domainTouchID"];
    [defaults synchronize];
    
    
    return changed;
}

@end
