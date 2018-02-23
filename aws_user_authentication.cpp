
#include <chrono>
#include <ctime>

#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

#include "aws_user_authentication.h"

static const std::string aws_secure_N = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" 
                                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" 
                                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                                        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                                        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                                        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                                        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                                        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                                        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                                        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                                        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                                        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

static std::string 
BinaryToHEXString(unsigned char* data, size_t bytes)
{
    std::stringstream ss;
    ss << std::hex;
    for (size_t i = 0; i < bytes / 2; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];
    return ss.str();
}


static void
ConvertHEXStringToCharVector(const std::string &hex_str,
                             std::vector<unsigned char> &output)
{
    const size_t input_length = hex_str.size();
    const size_t output_length = (input_length+1) / 2;
    output.resize(output_length);

    for (unsigned int i = 0; i < input_length; i += 2)
    {
        std::string byteString = hex_str.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), nullptr, 16);
        output[(i / 2)] = byte;
    }

}


namespace 
{
    struct BIOFreeAll { void operator()(BIO* p) { BIO_free_all(p); } };
}

static std::string 
Base64Encode(const std::vector<unsigned char> &binary)
{
    std::unique_ptr<BIO, BIOFreeAll> b64(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* sink = BIO_new(BIO_s_mem());
    BIO_push(b64.get(), sink);
    BIO_write(b64.get(), binary.data(), int(binary.size()));
    BIO_flush(b64.get());
    const char* encoded;
    const long len = BIO_get_mem_data(sink, &encoded);
    return std::string(encoded, len);
}

// Assumes no newlines or extra characters in encoded string
static std::vector<unsigned char> 
Base64Decode(const char* encoded)
{
    std::unique_ptr<BIO, BIOFreeAll> b64(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* source = BIO_new_mem_buf(encoded, -1); // read-only source
    BIO_push(b64.get(), source);
    const size_t maxlen = strlen(encoded) / 4 * 3 + 1;
    std::vector<unsigned char> decoded(maxlen);
    const int len = BIO_read(b64.get(), decoded.data(), int(maxlen));
    decoded.resize(len);
    return decoded;
}


static std::string 
PadHexStringWithLeadingZero(const std::string &hex_string)
{
    std::string output;
    char top = hex_string[0];
    if ((hex_string.size() % 2) == 1)
        output = "0" + hex_string;
    else if (top == '8' || top == '9' || top == 'a' || top == 'b' || top == 'c' || top == 'd' || top == 'e' || top == 'f' || top == 'A' || top == 'B' || top == 'C' || top == 'D' || top == 'E' || top == 'F')
        output = "00" + hex_string;
    else
        output = hex_string;

    return output;
}


static std::vector<unsigned char> 
PadCharVector(std::vector<unsigned char> &digest)
{
    std::vector<unsigned char> output;
    // convert to hex, pad then convert to unsigned char and output
    std::string hex_string = BinaryToHEXString(digest.data(), int(digest.size() * 2));
    hex_string = PadHexStringWithLeadingZero(hex_string);
    ConvertHEXStringToCharVector(hex_string, output);
    return output;
}

static void 
DigestMessage(const std::vector<unsigned char> &message, std::vector<unsigned char> &digest)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, message.data(), message.size());
    digest.resize(EVP_MD_size(EVP_sha256()));
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len);
    EVP_MD_CTX_destroy(mdctx);
}


static void 
DigestMessage(const std::string &message, std::vector<unsigned char> &digest)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, message.c_str(), message.size());
    digest.resize(EVP_MD_size(EVP_sha256()));
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len);
    EVP_MD_CTX_destroy(mdctx);
}


static void 
HKDF(const std::vector<unsigned char> &salt,
    const std::vector<unsigned char> &secret,
    const std::vector<unsigned char> &label,
    std::vector<unsigned char> &output)
{
    EVP_PKEY_CTX *pctx;
    output.resize(16);
    size_t outlen = output.size();
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), int(salt.size()));
    EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), int(secret.size()));
    EVP_PKEY_CTX_add1_hkdf_info(pctx, label.data(), int(label.size()));
    EVP_PKEY_derive(pctx, output.data(), &outlen);
}


AWSUserAuthentication::AWSUserAuthentication(const std::string &username, const std::string &password, const std::string &user_pool, const std::string client_id, const std::string region_id) :
    username_(username),
    password_(password),
    user_pool_(user_pool),
    client_id_(client_id),
    region_id_(region_id),
    bn_N_(BN_new()),
    bn_g_(BN_new()),
    bn_k_(BN_new()),
    bn_random_(BN_new()),
    bn_a_(BN_new()),
    bn_A_(BN_new())
{

}


AWSUserAuthentication::~AWSUserAuthentication()
{
    BN_free(bn_N_);
    BN_free(bn_g_);
    BN_free(bn_k_);
    BN_free(bn_random_);
    BN_free(bn_a_);
    BN_free(bn_A_);
}


void AWSUserAuthentication::GenerateSRPAValues()
{
    BN_rand(bn_random_, 256, 1, 1); // 256-bit random word
    BN_hex2bn(&bn_N_, aws_secure_N.c_str());
    BN_hex2bn(&bn_g_, "2");
    
    std::vector<unsigned char> ng_block;
    ConvertHEXStringToCharVector("00" + aws_secure_N + "02", ng_block);

    std::vector<unsigned char> k_vector; // k actually seems to be fixed, shouldn't really need to regenerate all the time
    DigestMessage(ng_block, k_vector);
    BN_bin2bn(k_vector.data(), int(k_vector.size()), bn_k_);

    BN_CTX * bn_ctx = BN_CTX_new();
    BN_mod(bn_a_, bn_random_, bn_N_, bn_ctx);
    
    // r = (a ^ b) mod p 
    BN_mod_exp(bn_A_, bn_g_, bn_a_, bn_N_, bn_ctx);
    
    srp_a_string_ = (BN_bn2hex(bn_a_));
    srp_A_string_ = (BN_bn2hex(bn_A_));

    // TODO add a do while loop here for safety, unlikely scenerio of A.Mod(N).Equals(0));

    BN_CTX_free(bn_ctx);
}

void
AWSUserAuthentication::getPasswordAuthenticationKey(const Aws::String &salt, 
                                                    const Aws::String &srp_b,
                                                    std::vector<unsigned char> &key)
{
    // generate the key required for hkdf, TODO can probably remove the copy here and create the concatanated string first
    std::string srp_A_string_pad = PadHexStringWithLeadingZero(srp_A_string_);
    std::string srp_b_string_pad = PadHexStringWithLeadingZero(srp_b); // can probably just add the hex strings... and convert to char
    std::string srp_A_srp_b = srp_A_string_pad + srp_b_string_pad;
    
    std::vector<unsigned char> array_srp_A_srp_b, u_digest;
    ConvertHEXStringToCharVector(srp_A_srp_b, array_srp_A_srp_b);
    DigestMessage(array_srp_A_srp_b, u_digest);
    u_digest = PadCharVector(u_digest);

    // TODO check for digest == zero

    const std::string userid_string = user_pool_ + username_ + ":" + password_;
    std::vector<unsigned char> userid_digest;
    DigestMessage(userid_string, userid_digest);
    
    std::vector<unsigned char> salt_array;
    ConvertHEXStringToCharVector(salt, salt_array);

    std::vector<unsigned char> x_array(salt_array.size() + userid_digest.size());
    std::vector<unsigned char> x_digest;
    std::copy(salt_array.begin(), salt_array.end(), x_array.begin());
    std::copy(userid_digest.begin(), userid_digest.end(), x_array.begin() + salt_array.size());
    DigestMessage(x_array, x_digest);
    x_digest = PadCharVector(x_digest);
    
    BIGNUM * bn_x(BN_new());
    BIGNUM * bn_u(BN_new());
    BIGNUM * bn_B(BN_new());

    BN_bin2bn(x_digest.data(), int(x_digest.size()), bn_x);
    BN_bin2bn(u_digest.data(), int(u_digest.size()), bn_u);
    BN_hex2bn(&bn_B, srp_b.c_str());

    BIGNUM * bn_g_mod_xn(BN_new());
    BIGNUM * bn_k_mult(BN_new());
    BIGNUM * bn_b_sub(BN_new());
    BIGNUM * bn_u_x(BN_new());
    BIGNUM * bn_a_add(BN_new());
    BIGNUM * bn_b_sub_modpow(BN_new());
    BIGNUM * bn_S(BN_new());

    // now do the math...
    BN_CTX * bn_ctx = BN_CTX_new();
    BN_mod(bn_a_, bn_random_, bn_N_, bn_ctx);

    BN_mod_exp(bn_g_mod_xn, bn_g_, bn_x, bn_N_, bn_ctx);
    BN_mul(bn_k_mult, bn_k_, bn_g_mod_xn, bn_ctx);
    BN_sub(bn_b_sub, bn_B, bn_k_mult);

    BN_mul(bn_u_x, bn_u, bn_x, bn_ctx);
    BN_add(bn_a_add, bn_a_, bn_u_x);
    BN_mod_exp(bn_b_sub_modpow, bn_b_sub, bn_a_add, bn_N_, bn_ctx);

    BN_mod(bn_S, bn_b_sub_modpow, bn_N_, bn_ctx);

    const std::string hex_s = std::string(BN_bn2hex(bn_S));
    std::vector<unsigned char> s_char;
    ConvertHEXStringToCharVector(hex_s, s_char);
    s_char = PadCharVector(s_char);
    
    const std::string dervied_key_info_str = "Caldera Derived Key";
    std::vector<unsigned char> dervied_key_info(dervied_key_info_str.begin(), dervied_key_info_str.end());

    // now get the hashed key 
    HKDF(u_digest, s_char, dervied_key_info, key);
    
    BN_free(bn_x);
    BN_free(bn_u);
    BN_free(bn_B);

    BN_free(bn_g_mod_xn);
    BN_free(bn_k_mult);
    BN_free(bn_b_sub);
    BN_free(bn_u_x);
    BN_free(bn_a_add);
    BN_free(bn_b_sub_modpow);
    BN_free(bn_S);

    BN_CTX_free(bn_ctx);

    //Debug information, remove when confident this is all working as required
    //std::cout << "u_content: " << BinaryToHEXString(content.data(), content.size() * 2) << std::endl;
    //std::cout << "u_digest: " << BinaryToHEXString(u_digest.data(), u_digest.size() * 2) << std::endl;
    //std::cout << "s_char: " << BinaryToHEXString(s_char.data(), s_char.size() * 2) << std::endl;
    //std::cout << "dervied_key_info: " << BinaryToHEXString(dervied_key_info.data(), dervied_key_info.size() * 2) << std::endl;
}
    


Aws::String 
AWSUserAuthentication::GenerateChallengeParameters( const Aws::String &salt,
                                                    const Aws::String &srp_b,
                                                    const Aws::String &secret_block,
                                                    const Aws::String &time_str)
{
    // convert the secret block from base64 into hex
    std::vector<unsigned char> secret_block_char;
    secret_block_char = Base64Decode(secret_block.c_str());
    
    std::vector<unsigned char> key;
    getPasswordAuthenticationKey(salt, srp_b, key);
    
    // hmac  
    std::vector<unsigned char> content(user_pool_.size() + username_.size() + secret_block_char.size() + time_str.size());
    std::copy(user_pool_.begin(), user_pool_.end(), content.begin());
    std::copy(username_.begin(), username_.end(), content.begin() + user_pool_.size());
    std::copy(secret_block_char.begin(), secret_block_char.end(), content.begin() + user_pool_.size() + username_.size());
    std::copy(time_str.begin(), time_str.end(), content.begin() + user_pool_.size() + username_.size() + secret_block_char.size());

    std::vector<unsigned char> hmac(32); // sha256 will make produce a 32 byte array 
    HMAC(EVP_sha256(), key.data(), int(key.size()), content.data(), int(content.size()), hmac.data(), nullptr);

    // now base64 encode the hmac to create the claim to return to aws
    std::string claim = Base64Encode(hmac); 

    //DEBUG information, leave here in case errors need to be tracked down
    //std::cout << "secbloc: " << BinaryToHEXString(secret_block_char.size(), secret_block_char.size() * 2) << std::endl;
    //std::cout << "key: " << BinaryToHEXString(key.size(), key.size() * 2) << std::endl;
    //std::cout << "content: " << BinaryToHEXString(content.size(), content.size() * 2) << std::endl;
    //std::cout << "hmac: " << BinaryToHEXString(hmac.size(), hmac.size() * 2) << std::endl;
    //std::cout << "claim : " << claim << std::endl;

    return claim;
}


int AWSUserAuthentication::InitiateAuthentication()
{
    Aws::SDKOptions options;
    Aws::InitAPI(options);
    {
        Aws::Client::ClientConfiguration clientConfig;
        clientConfig.region = region_id_;

        Aws::Map<Aws::String, Aws::String> request_parameters;
        request_parameters["USERNAME"] = username_;
        request_parameters["SRP_A"] = srp_A_string_;

        cognito_client_ = std::make_shared<Aws::CognitoIdentityProvider::CognitoIdentityProviderClient>(clientConfig);
        Aws::CognitoIdentityProvider::Model::InitiateAuthRequest auth_request;
        auth_request.SetClientId(client_id_);
        auth_request.SetAuthFlow(Aws::CognitoIdentityProvider::Model::AuthFlowType::USER_SRP_AUTH);
        auth_request.SetAuthParameters(request_parameters);

        auto auth_request_result = cognito_client_->InitiateAuth(auth_request);
        if (auth_request_result.IsSuccess())
        {
            std::map<Aws::String, Aws::String> challenge_map  = auth_request_result.GetResult().GetChallengeParameters();

            // need time in the following format - Mon Jan 8 09:51:39 UTC 2018
            std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            
            struct tm timeinfo;
            localtime_s(&timeinfo, &now_c); // using thread-safe localtime_s over localtime
            ss << std::put_time(&timeinfo, "%a %b %e %H:%M:%S UTC %Y");
            std::string time_str(ss.str());

            const Aws::String salt = challenge_map["SALT"];
            const Aws::String srp_b = challenge_map["SRP_B"];
            const Aws::String secret_block = challenge_map["SECRET_BLOCK"];

            Aws::String claim64 = GenerateChallengeParameters(salt,
                                                              srp_b,
                                                              secret_block,
                                                              time_str);

            // now set the return to the challenge
            Aws::CognitoIdentityProvider::Model::RespondToAuthChallengeRequest challenge_request;
            challenge_request.SetClientId(client_id_);
            challenge_request.SetChallengeName(auth_request_result.GetResult().GetChallengeName());
            challenge_request.AddChallengeResponses("PASSWORD_CLAIM_SECRET_BLOCK", secret_block);
            challenge_request.AddChallengeResponses("PASSWORD_CLAIM_SIGNATURE", claim64);
            challenge_request.AddChallengeResponses("USERNAME", username_);
            challenge_request.AddChallengeResponses("TIMESTAMP", time_str);

            auto challenge_request_result = cognito_client_->RespondToAuthChallenge(challenge_request);
            if (challenge_request_result.IsSuccess())
            {
                std::cout << "User logged in!" << std::endl;
                std::cout << "The token can now be exchanged for AWS Credentials" << std::endl;
                std::cout << "The ID Token: " << challenge_request_result.GetResult().GetAuthenticationResult().GetIdToken() << std::endl;
            }
            else
            {
                std::cout << "Failed to respond to the challenge" << std::endl;
                std::cout << "Request error: " <<
                    challenge_request_result.GetError().GetExceptionName() << " " <<
                    challenge_request_result.GetError().GetMessage() << std::endl;
                return 1;
            }
        }
        else
        {
            std::cout << "Failed to init the authenticate the user" << std::endl;
            std::cout << "Request error: " <<
                auth_request_result.GetError().GetExceptionName() << " " <<
                auth_request_result.GetError().GetMessage() << std::endl;
            return 1;
        }
    }

    Aws::ShutdownAPI(options);
    return 0;
}


