 /*
  * Copyright 2018 https://github.com/manishpin
  *
  * Licensed under the Apache License, Version 2.0 (the "License").
  * You may not use this file except in compliance with the License.
  * A copy of the License is located at
  *
  *  http://aws.amazon.com/apache2.0
  *
  * or in the "license" file accompanying this file. This file is distributed
  * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
  * express or implied. See the License for the specific language governing
  * permissions and limitations under the License.
  */

#pragma once

#ifndef __AWSUSERAUTHENTICATION__
#define __AWSUSERAUTHENTICATION__


#include <iostream>
#include <iomanip>

#include <aws/s3/S3Client.h> // this is required to resolve errors with the AWSError, shouldn't be required here

#include <aws/cognito-idp/CognitoIdentityProviderClient.h>
#include <aws/cognito-idp/model/InitiateAuthRequest.h>
#include <aws/cognito-idp/model/InitiateAuthResult.h>
#include <aws/cognito-idp/model/RespondToAuthChallengeRequest.h>
#include <aws/cognito-idp/model/RespondToAuthChallengeResult.h>
#include <aws/cognito-idp/model/AdminInitiateAuthRequest.h>
#include <aws/cognito-idp/model/SignUpRequest.h>
#include <aws/cognito-idp/model/ConfirmSignUpRequest.h>
#include <aws/cognito-idp/model/ListUsersRequest.h>

#include <aws/cognito-identity/model/GetIdRequest.h>
#include <aws/cognito-identity/model/GetOpenIdTokenRequest.h>
#include <aws/cognito-identity/model/GetCredentialsForIdentityRequest.h>

#include <aws/core/Aws.h>

#include <openssl/bn.h>

class Aws::CognitoIdentityProvider::CognitoIdentityProviderClient;

class AWSUserAuthentication
{

public:

    AWSUserAuthentication(const std::string &username, const std::string &password, const std::string &user_pool, const std::string client_id, const std::string region_id);
    ~AWSUserAuthentication();

    void GenerateSRPAValues();
    int  InitiateAuthentication();

    Aws::String GenerateChallengeParameters(const Aws::String &salt,
                                            const Aws::String &srp_b,
                                            const Aws::String &secret_block,
                                            const Aws::String &time_str);

    void AWSUserAuthentication::getPasswordAuthenticationKey(const Aws::String &salt, const Aws::String &srp_b, std::vector<unsigned char> &key);

private:

    std::string username_;
    std::string password_;
    std::string user_pool_;
    std::string client_id_;
    std::string region_id_;

    BIGNUM * bn_N_;
    BIGNUM * bn_g_;
    BIGNUM * bn_k_;
    BIGNUM * bn_random_;

    BIGNUM * bn_a_;
    BIGNUM * bn_A_;

    std::string srp_a_string_;
    std::string srp_A_string_;

    std::shared_ptr<Aws::CognitoIdentityProvider::CognitoIdentityProviderClient> cognito_client_;

};


#endif // __AWSUSERAUTHENTICATION__