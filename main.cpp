#include <GLFW/glfw3.h>
#include <iostream>
#include <vector>
#include <string.h>
#include <string>
#include <cstring>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

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







std::string toHexStrDebug(const unsigned char* hash, size_t len) {
    std::stringstream ss;
    for(size_t i = 0; i < len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

std::string bruteForceOpenSSLHash(
    const char* dict,
    size_t dictSize,
    size_t pwdLength,
    int passSide,
    int dicSide,
    const unsigned char* targetHash,
    size_t hashLen,
    const EVP_MD* md,
    bool debug) 
{
    std::string candidate(pwdLength, ' ');
    std::vector<size_t> idx(pwdLength, 0);
    
    // Подготовка словаря
    std::vector<char> actualDict(dictSize);
    for(size_t i = 0; i < dictSize; ++i) {
        actualDict[i] = (dicSide == 1) ? dict[i] : dict[dictSize - 1 - i];
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char curHash[EVP_MAX_MD_SIZE];
    unsigned int currentHashLen;
    size_t attempts = 0;

    
    std::string targetHex = "";
    if (hashLen > 30) { 
        targetHex = std::string(reinterpret_cast<const char*>(targetHash));
    } else { 
        targetHex = toHexStrDebug(targetHash, hashLen);
    }
    targetHex.erase(std::remove_if(targetHex.begin(), targetHex.end(), ::isspace), targetHex.end());

    while (true) {
        for (size_t i = 0; i < pwdLength; ++i) {
            candidate[i] = actualDict[idx[i]];
        }

        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, candidate.c_str(), candidate.size());
        EVP_DigestFinal_ex(ctx, curHash, &currentHashLen);

        std::string currentHex = toHexStrDebug(curHash, currentHashLen);
        attempts++;

        if (debug) {
            std::cout << "Attempt " << attempts << ": [" << candidate << "] -> " << currentHex << "\n";
        }

        if (currentHex == targetHex) {
            std::cout << "\n\n" << std::string(40, '!') << std::endl;
            std::cout << "MATCH FOUND! PASSWORD IS: " << candidate << std::endl;
            std::cout << std::string(40, '!') << "\n\n" << std::endl;
            
            EVP_MD_CTX_free(ctx);
            return candidate; 
        }

        // Одометр
        bool carry = true;
        if (passSide == 1) { // L-to-R
            for (int pos = (int)pwdLength - 1; pos >= 0 && carry; --pos) {
                if (++idx[pos] == dictSize) { idx[pos] = 0; } 
                else { carry = false; }
            }
        } else { // R-to-L
            for (size_t pos = 0; pos < pwdLength && carry; ++pos) {
                if (++idx[pos] == dictSize) { idx[pos] = 0; } 
                else { carry = false; }
            }
        }
        if (carry) break; 
    }

    EVP_MD_CTX_free(ctx);
    return "NOT_FOUND";
}








int main(void){

    int user_action_number = 0;
    int user_action_bf_method = 0;
    std::string str_for_encode = "system_▀";
    int hash_type = 0;
    std::string enc_str="system_▀";

    int bf_pass_lenght = -10;
    int pass_bf_side=-10;
    int dic_bf_side=-10;
    std::string c_dic_list="system_▀";

    std::string bfrtout="system_▀";

    bool debug_state= false;

 

    while (true){
    std::cout << "Hi! this a pentest instrument,okey,just select what need for u,select Number. \n";
    std::cout <<"1: Change and run (3,it not count) BruteForce Method. \n";
    std::cout <<"2: Encode hash from str. \n";
    std::cout <<"6: print somethink datas. \n";
    //std::cout <<"3: BruteForce hash, Start Attack.  \n";
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
            std::cout << "select lenght_int_pass: ";
            std::cin >> bf_pass_lenght;
            std::cout << "\nselect pass_bf_side(left-to-right,right-to-left)(1 or 2) ::: ";
            std::cin >> pass_bf_side;
            std::cout << "\n select dic_bf_side(left-to-right,right-to-left)(1 or 2) ::: ";
            std::cin >> dic_bf_side;
            std::cout << "\nwrite here dic_list:  \n ~~~  (";
            std::cin >> c_dic_list;
            std::cout << "\n\n\ndebug state 1 or 0(false):  \n ~~~  ";
            std::cin >> debug_state;
            std::cout <<");\n\n";
            std::cout << "please_wait_all_settuping;\n\n\n\n\n";

            //

            size_t hash_length = enc_str.length();

            if (hash_type == 1) {
                bfrtout = bruteForceOpenSSLHash(
                    c_dic_list.c_str(),
                    c_dic_list.size(),
                    bf_pass_lenght,
                    pass_bf_side,
                    dic_bf_side,
                    reinterpret_cast<const unsigned char*>(enc_str.data()),
                    hash_length,
                    EVP_md5(),
                    debug_state
                );
            }
            else if (hash_type == 2) {
                bfrtout = bruteForceOpenSSLHash(
                    c_dic_list.c_str(),
                    c_dic_list.size(),
                    bf_pass_lenght,
                    pass_bf_side,
                    dic_bf_side,
                    reinterpret_cast<const unsigned char*>(enc_str.data()),
                    hash_length,
                    EVP_sha256(),
                    debug_state
                );

            }
            std::cout<<"\n\n"<<bfrtout<<"\n\n";
            
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
    if (user_action_number==6){
        std::cout<<"\n\n\n\n";
        std::cout<<enc_str<<"\n";
        std::cout<<bfrtout<<"\n";
        //std::cout<<
        //std::cout<<
        //std::cout<<
        //std::cout<<
        //std::cout<<
        std::cout<<"\n\n\n\n";     
    }


    }


    return 0;
 }
