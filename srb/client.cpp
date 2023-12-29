#include <tfhe/tfhe_core.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <iostream>
#include <time.h>
#include <vector>
#include <cassert>
#include <string>
#include <string.h>
#include <stdint.h>
#include "openssl/md5.h"  
#include "openssl/sha.h" 
#include "openssl/hmac.h"
#include "openssl/evp.h"
#include <iomanip>
#include <map>
#include <math.h>
#include <sstream>
#include <gmp.h>
#include <gmpxx.h>
#include <sys/time.h>
#include <fstream>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <bitset>
#include <stack> 

//The number of file
#define MAX_FILE_LEN 2
#define LEN_OF_SEED 10

//The number of entries
#define MAX_TIMES 2

double totalupdatetime = 0;

double clientsearch = 0;
double serversearch = 0;
double totalsearch = 0;

using namespace std;

//transform number to string
string num2str(int a)
{
	string str;
    stringstream ss;
    ss << a;
    ss >> str;
    return str;
}

//hex into bin
string hex2bin(string str)
{
	string s = "";
	for(int i = 0;i<str.length();i++)
	{
		int tmp = 0;
		string rtmp = "";
		if(str[i]>='a'&&str[i]<='f')
		{
			tmp = int(str[i]-'a')+10;
		}
		else
		{
			tmp = int(str[i]-'0');
		}
		while(tmp!=0)
		{
			int bit = tmp&1;
			rtmp = char(bit+48)+rtmp;
			tmp = tmp>>1;
		}
		int yu = 4-rtmp.length();
		for(int j = 0;j<yu;j++)
		{
			rtmp = '0'+rtmp;
		}
		s = s+rtmp;
	}
	return s;
}

//bin into hex
string bin2hex(string str)
{
	string result = "";
	for(int i = 0;i<str.length();i=i+4)
	{
		int q = 0;
		for(int j = 0;j<4;j++)
		{
			q+=pow(2,3-j)*int(str[i+j]-'0');
		}
		if(q>=0&&q<=9)
		{
			result+=char(48+q);
		}
		else
		{
			result+=char(97+q-10);
		}
	}
	return result;
}


string sha256(const string str)
{
	stringstream ss;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << setw(2) << setfill('0') << hex << static_cast<int> (hash[i]);
    }
	return ss.str();
}

string hmac256(string key, string msg)
{
	stringstream ss;
    HMAC_CTX *ctx;
	ctx = HMAC_CTX_new();
    unsigned int  len;
    unsigned char out[EVP_MAX_MD_SIZE];
    HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha256(),NULL);
    HMAC_Update(ctx, (unsigned char*)msg.c_str(), msg.length());
    HMAC_Final(ctx, out, &len);
	HMAC_CTX_free(ctx);
    for (unsigned int i = 0;  i < len;  i++)
    {
        ss << setw(2) << setfill('0') << hex << static_cast<int> (out[i]);
    }
    return ss.str();
}

string hmac512(string key, string msg)
{
	stringstream ss;
    HMAC_CTX *ctx;
	ctx = HMAC_CTX_new();
    unsigned int  len;
    unsigned char out[EVP_MAX_MD_SIZE];
    HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha512(),NULL);
    HMAC_Update(ctx, (unsigned char*)msg.c_str(), msg.length());
    HMAC_Final(ctx, out, &len);
	HMAC_CTX_free(ctx);
    for (unsigned int i = 0;  i < len;  i++)
    {
        ss << setw(2) << setfill('0') << hex << static_cast<int> (out[i]);
    }
    return ss.str();
}

string H_1(string key, string msg)
{
	return hmac256(key, msg);
}

string H_2(string key, string msg)
{
	string CT = hmac512(key, msg);
	return CT.substr(0, CT.length()/2);
}

//Cal xor of two hex string
string Strxor(string s1,string s2)
{
	string bin1 = hex2bin(s1);
	string bin2 = hex2bin(s2);
	string r = "";
	for(int i = 0;i<bin1.length();i++)
	{
		int tmp = int(bin1[i]-'0')^int(bin2[i]-'0');
		r+=char(tmp+48);
	}
	return bin2hex(r);
}

string rand_str(const int len)  /*参数为字符串的长度*/
{
    /*初始化*/
    string str;                 /*声明用来保存随机字符串的str*/
    char c;                     /*声明字符c，用来保存随机生成的字符*/
    int idx;                    /*用来循环的变量*/
	srand((int)time(0));
    for(idx = 0;idx < len;idx ++)
    {
        c = 'a' + rand()%26;
        str.push_back(c);       /*push_back()是string类尾插函数。这里插入随机字符c*/
    }
    return str;                 /*返回生成的随机字符串*/
}

//generate random str
string rand_str2(const int len)
{
	clock_t time = clock();
    gmp_randstate_t grt;
    gmp_randinit_default(grt);
    gmp_randseed_ui(grt, time);

	mpz_t num;
	mpz_init2(num,len);
	mpz_urandomb(num,grt,len);

	char* numstr = new char[len];
	mpz_get_str(numstr,10,num);

	string sp = numstr;
	return sp;
}

string PRF(string key, string msg)
{
	stringstream ss;
    HMAC_CTX *ctx;
	ctx = HMAC_CTX_new();
    unsigned int  len;
    unsigned char out[EVP_MAX_MD_SIZE];
    HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_md5(),NULL);
    HMAC_Update(ctx, (unsigned char*)msg.c_str(), msg.length());
    HMAC_Final(ctx, out, &len);
	HMAC_CTX_free(ctx);
    for (unsigned int i = 0;  i < len;  i++)
    {
        ss << setw(2) << setfill('0') << hex << static_cast<int> (out[i]);
    }
    return ss.str();
}

class Client
{
	public:
	string ST_c;
    int counter;
	string keyword;

	string K;

	TFheGateBootstrappingSecretKeySet* key;
	const TFheGateBootstrappingCloudKeySet* bk;



	int init(string word)
    {
		//Generate key for fully homomorphic encryption
        const int minimum_lambda = 110;
        TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
        uint32_t seed[] = { 314, 1592, 657 };
        tfhe_random_generator_setSeed(seed,3);
        key = new_random_gate_bootstrapping_secret_keyset(params);
		bk = &key->cloud;

		counter = -1;
        string in = rand_str(10);
		string in2 = rand_str(10);

        ST_c = sha256(in2);
		K = sha256(in);

		keyword = word;

        return 1;
    }
};

class CTelement
{
	public:
	string C_ST_C;
	LweSample* Vc;
	LweSample* Vd;
};

void Update(Client &client,map<string,CTelement> &Server)
{
    int timecount;
    double start, end,startf,endf,startt,endt;
	struct timeval t1,t2;
	string in = rand_str2(LEN_OF_SEED);

	clock_t time = clock();
    gmp_randstate_t grt;
    gmp_randinit_default(grt);
    gmp_randseed_ui(grt, time);

	//Generate random operation
    mpz_t va,vb;

    mpz_init2(va, MAX_FILE_LEN);               //random operation a and operation b
    mpz_init2(vb, MAX_FILE_LEN);
    mpz_urandomb(va,grt,MAX_FILE_LEN);
    mpz_urandomb(vb,grt,MAX_FILE_LEN);

	gettimeofday(&t1,NULL);

	//Generate token
	string ST_new = "";
    ST_new = sha256(in);

	string Keys = PRF(client.K, client.keyword);

	client.counter++;
	string UT_new = H_1(Keys, ST_new);
	string C_ST_c = Strxor(H_2(Keys, ST_new),client.ST_c);
	client.ST_c = ST_new;

	CTelement cc;
	cc.C_ST_C = C_ST_c;

	//Encryption
	cc.Vc = new_gate_bootstrapping_ciphertext_array(MAX_FILE_LEN, client.bk->params);
	cc.Vd = new_gate_bootstrapping_ciphertext_array(MAX_FILE_LEN, client.bk->params);

	for(int i = 0;i<MAX_FILE_LEN;i++)
    {
        bootsSymEncrypt(&cc.Vc[i], mpz_tstbit(va,i), client.key);
        bootsSymEncrypt(&cc.Vd[i], mpz_tstbit(vb, i), client.key);
    }
	cout<<endl;

	Server[UT_new] = cc;

	gettimeofday(&t2,NULL);

	totalupdatetime += (t2.tv_sec - t1.tv_sec) + (double)(t2.tv_usec - t1.tv_usec)/1000000.0;
	
	return;
}

void Search(Client &client, map<string,CTelement> &Server)
{
	int timecount = client.counter;
	struct timeval t1,t2,t3,t4;

	string in = rand_str2(LEN_OF_SEED);
	string in2 = rand_str2(LEN_OF_SEED+1);

    gettimeofday(&t1,NULL);
	string new_ST = sha256(in2);

	string Keys = PRF(client.K, client.keyword);

	string ST_temp = client.ST_c;
	string New_UT = H_1(Keys, new_ST);
	string new_CT = "0000000000000000";  //new token generation

	client.counter++;

	CTelement cc;

	cc.C_ST_C = new_CT;
	cc.Vc = new_gate_bootstrapping_ciphertext_array(MAX_FILE_LEN, client.bk->params);
	cc.Vd = new_gate_bootstrapping_ciphertext_array(MAX_FILE_LEN, client.bk->params);

	for(int i = 0;i<MAX_FILE_LEN;i++)
    {
        bootsSymEncrypt(&cc.Vc[i], 0, client.key);
        bootsSymEncrypt(&cc.Vd[i], 0, client.key);
    }

	gettimeofday(&t2,NULL);

	stack<LweSample*> Vaa;
	stack<LweSample*> Vbb;

	for(int q = timecount;q>=0;q--)
	{
		string UT = H_1(Keys, ST_temp);
		string C_ST = Server[UT].C_ST_C;
		ST_temp = Strxor(C_ST, H_2(Keys, ST_temp));

		Vaa.push(Server[UT].Vc);
		Vbb.push(Server[UT].Vd);

		if(C_ST=="0000000000000000")
		{
			break;
		}
		//Server.erase(UT);
	}

	while(!Vaa.empty())
	{
		LweSample *tmp1 = new_gate_bootstrapping_ciphertext_array(MAX_FILE_LEN, client.bk->params);
        LweSample *tmp2 = new_gate_bootstrapping_ciphertext_array(MAX_FILE_LEN, client.bk->params);
		LweSample *tmp3 = new_gate_bootstrapping_ciphertext_array(MAX_FILE_LEN, client.bk->params);

		for(int i = 0; i<MAX_FILE_LEN;i++)
        {
            bootsAND(&tmp1[i], &Vaa.top()[i], &Vbb.top()[i], client.bk);

            bootsNOT(&tmp2[i], &Vaa.top()[i], client.bk);

			bootsAND(&cc.Vc[i], &cc.Vc[i], &tmp2[i], client.bk);

			bootsXOR(&cc.Vc[i], &cc.Vc[i], &tmp1[i], client.bk);
        }
		Vaa.pop();
		Vbb.pop();
	}
	for(int i = 0;i<MAX_FILE_LEN;i++)
	{
		bootsCOPY(&cc.Vd[i], &cc.Vc[i], client.bk);
	}

	Server[New_UT] = cc;
	Server.clear();

	gettimeofday(&t3,NULL);
	for(int j = 0;j<MAX_FILE_LEN;j++)
	{
		int am = bootsSymDecrypt(&cc.Vc[j], client.key);
		int bm = bootsSymDecrypt(&cc.Vd[j], client.key);
	}
	gettimeofday(&t4,NULL);

	clientsearch+=(t2.tv_sec - t1.tv_sec) + (double)(t2.tv_usec - t1.tv_usec)/1000000.0+(t4.tv_sec - t3.tv_sec) + (double)(t4.tv_usec - t3.tv_usec)/1000000.0;
	serversearch+=(t3.tv_sec - t2.tv_sec) + (double)(t3.tv_usec - t2.tv_usec)/1000000.0;
	totalsearch=clientsearch+serversearch;

	return;
}

int main()
{
	map<string, Client> CT;
	string word = "dhc";    //get from erone data
    Client c;
    c.init(word);
	CT[word] = c;

    map<string,CTelement> Server;
    for(int times = 0;times<MAX_TIMES;times++)   
	{
        Update(c,Server);
	}
	// cout<<"total update: "<<totalupdatetime<<"s"<<endl;
	// cout<<"Average update: "<<totalupdatetime/MAX_TIMES<<"s"<<endl;
	Search(c,Server);
	// cout<<"client search: "<<clientsearch<<"s"<<endl;
	// cout<<"server search: "<<serversearch<<"s"<<endl;
	// cout<<"total search: "<<totalsearch<<"s"<<endl;
}
