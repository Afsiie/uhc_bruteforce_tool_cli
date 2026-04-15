#include <GLFW/glfw3.h>
#include <iostream>
#include <vector>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

std::string encode_hash_fstr_md5(const std::string& str_for_encode){
    unsigned char digest[MD5_DIGEST_LENGTH];

    MD5(reinterpret_cast<const unsigned char*>(str_for_encode.c_str()),
        str_for_encode.size(),
        digest);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        oss << std::setw(2) << static_cast<int>(digest[i]);
    }

    return oss.str();
}

std::string encode_hash_fstr_sha_256(const std::string& str_for_encode)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx,
        reinterpret_cast<const unsigned char*>(str_for_encode.c_str()),
        str_for_encode.size());
    EVP_DigestFinal_ex(ctx, hash, &length);

    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (unsigned int i = 0; i < length; i++)
    {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }

    return oss.str();
}

int main(void){

    int user_action_number = 0;
    int user_action_bf_method = 0;
    std::string str_for_encode = "system_▀";
    int hash_type = 0;
    std::string enc_str="system_▀";


    while (true){
    std::cout << "Hi! this a pentest instrument,okey,just select what need for u,select Number. \n";
    std::cout <<"1: Change BruteForce Method. \n";
    std::cout <<"2: Encode hash from str. \n";
    std::cout <<"3: BruteForce hash, Start Attack.  \n";
    std::cout <<"4: Change current hash type for actions.  \n \n ";

    std::cout <<"~~~ ";

    std::cin >> user_action_number;

    if (user_action_number == 0){
        std::cout <<"FUUUUUUUUUUUUUCk.";
        return 1;
    }
    else if (user_action_number == 1){
        std::cout <<"Please select bf method from list: \n\n";
        std::cout <<"1: attack by dictionary(chars massive,lenght,pass_side,dic_side);\n";
        std::cout <<"2: not realized; \n";
        
        std::cout <<"\n\n~~~ ";

        std::cin >> user_action_bf_method;

        if (user_action_bf_method==1){
            std::cout << "setted; \n\n\n\n\n";

        }

    }
    else if (user_action_number == 2){
        std::cout <<"Please enter str for encode: ~~~ ";
        std::cin >> str_for_encode;

        if (str_for_encode!="system_▀"){
            std::cout <<"encoding...; \n\n\n";

            if (hash_type==0){
                std::cout <<"error_0notallowed;\n\n\n";
                break;
            }
            else if (hash_type==1){
                enc_str = encode_hash_fstr_md5(str_for_encode);
                std::cout << "md5_hash:  " << enc_str << "   ;\n\n\n";
                
            }
            else if (hash_type==2){
                enc_str = encode_hash_fstr_sha_256(str_for_encode);
                std::cout << "sha-256_hash:  " << enc_str << "   ;\n\n\n";
                
            }
            

        }
        
    }
    else if (user_action_number==4){
        std::cout <<"Please select hash type from list: \n\n";
        std::cout <<"1: MD5;\n";
        std::cout <<"2: SHA-256;\n";


        std::cin >> hash_type;

        std::cout <<"setted; \n\n";


    }

    }


    return 0;
 }
