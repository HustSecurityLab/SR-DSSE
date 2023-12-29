#include </usr/local/include/cuFHE/cufhe_gpu.cuh>
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
#include <unordered_map>

#define MAX_FILE_LEN 1000
#define LEN_OF_SEED 10
#define MAX_TIMES 20

using namespace std;
using namespace cufhe;

float totalupdatetime = 0;
float clientsearch = 0;
float serversearch = 0;
float totalsearch = 0;

string num2str(int a)
{
	string str;
    stringstream ss;
    ss << a;
    ss >> str;
    return str;
}

//md5
void md5(const string &srcStr, string &encodedHexStr)
{
	unsigned char mdStr[33] = { 0 };
	MD5((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);// 调用md5哈希
	string encodedStr = std::string((const char *)mdStr);// 哈希后的字符串
	char buf[65] = { 0 };
	char tmp[3] = { 0 };
	for (int i = 0; i < 32; i++)// 哈希后的十六进制串 32字节  
	{
		sprintf(tmp, "%02x", mdStr[i]);
		strcat(buf, tmp);
	}
	buf[32] = '\0'; // 后面都是0，从32字节截断  
	encodedHexStr = std::string(buf);
}

string sha256(const string str)
{
	char buf[10000];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::string NewString = "";
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(buf,"%02x",hash[i]);
        NewString = NewString + buf;
    }
	return NewString;
}

string sha512(const string str)
{
	char buf[10000];
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, str.c_str(), str.size());
    SHA512_Final(hash, &sha512);
    std::string NewString = "";
    for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
    {
        sprintf(buf,"%02x",hash[i]);
        NewString = NewString + buf;
    }
	return NewString;
}

string newxor(string s1, string s2)
{
	mpz_t ss1,ss2,ssf;
	char* result = new char[1000];
	mpz_init(ss1);
	mpz_init(ss2);
	mpz_init(ssf);
	mpz_set_str(ss1, s1.c_str(), 16);
	mpz_set_str(ss2, s2.c_str(), 16);
	mpz_xor(ssf,ss1,ss2);
	mpz_get_str(result, 16, ssf);
	string fr = result;

	for(int i = fr.length();i<128;i++)
	{
		fr = "0"+fr;
	}

	return fr;
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
	return hmac512(key, msg);
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

	PriKey pri_key; // private key
	PubKey pub_key; // public key

	int init(string word)
    {
    	counter = -1;
        string in = rand_str(10);
		string in2 = rand_str(10);

        ST_c = sha512(in2);
		K = sha256(in);

		keyword = word;

		SetSeed(); // set random seed
		KeyGen(pub_key, pri_key);
		Initialize(pub_key);
        return 1;
    }
};

class CTelement
{
	public:
	string C_ST_C;
	Ctxt* Vc = new Ctxt[MAX_FILE_LEN];
	Ctxt* Vd = new Ctxt[MAX_FILE_LEN];
};

void Update(Client &client,unordered_map<string,CTelement> &Server)
{
	string in = rand_str2(LEN_OF_SEED);
	
	clock_t time = clock();
    gmp_randstate_t grt;
    gmp_randinit_default(grt);
    gmp_randseed_ui(grt, time);

    mpz_t va,vb;

    mpz_init2(va, MAX_FILE_LEN);               //random operation a and operation b
    mpz_init2(vb, MAX_FILE_LEN);
    mpz_urandomb(va,grt,MAX_FILE_LEN);
    mpz_urandomb(vb,grt,MAX_FILE_LEN);

	Ptxt* pt = new Ptxt[MAX_FILE_LEN];
	Ptxt* pt2 = new Ptxt[MAX_FILE_LEN];
	for(int i = 0;i<MAX_FILE_LEN;i++)
    {
        pt[i] = mpz_tstbit(va, i);
        pt2[i] = mpz_tstbit(vb, i);
    }


	float et;
  	cudaEvent_t start, stop;
  	cudaEventCreate(&start);
  	cudaEventCreate(&stop);
  	cudaEventRecord(start, 0);

	//Generate token
	string ST_new = "";
    ST_new = sha512(in);

	string Keys = PRF(client.K, client.keyword);

	client.counter++;
	string UT_new = H_1(Keys, ST_new);
	string C_ST_c = newxor(H_2(Keys, ST_new),client.ST_c);
	client.ST_c = ST_new;

	CTelement cc;
	cc.C_ST_C = C_ST_c;

	for(int i = 0;i<MAX_FILE_LEN;i++)
    {
        Encrypt(cc.Vc[i], pt[i], client.pri_key);
		Encrypt(cc.Vd[i], pt2[i], client.pri_key);
    }

	Server[UT_new] = cc;

	cudaEventRecord(stop, 0);
  	cudaEventSynchronize(stop);
  	cudaEventElapsedTime(&et, start, stop);

	totalupdatetime+=et;

	return;
}

void Search(Client &client, unordered_map<string,CTelement> &Server)
{
	int timecount = client.counter;
	float et1, et2, et3;
	cudaEvent_t start1, stop1, start2, stop2, start3, stop3;
  	cudaEventCreate(&start1);
  	cudaEventCreate(&stop1);
   
	string in = rand_str2(LEN_OF_SEED);
	string in2 = rand_str2(LEN_OF_SEED+1);

	Ptxt* pt = new Ptxt[MAX_FILE_LEN];
	Ctxt* Vc = new Ctxt[MAX_FILE_LEN];
	for(int i = 0;i<MAX_FILE_LEN;i++)
    {
        pt[i] = 0;
    }

	cudaEventRecord(start1, 0);

	//string new_ST = sha256(in2);

	string Keys = PRF(client.K, client.keyword);

	string ST_temp = client.ST_c;
	string UT_c = "";
	//string New_UT = H_1(Keys, new_ST);
	//string new_CT = "0000000000000000";  //new token generation

	//client.counter++;

	// CTelement cc;
	// cc.C_ST_C = new_CT;

	for(int i = 0;i<MAX_FILE_LEN;i++)
    {
        Encrypt(Vc[i], pt[i], client.pri_key);
    }

	cudaEventRecord(stop1, 0);
  	cudaEventSynchronize(stop1);
  	cudaEventElapsedTime(&et1, start1, stop1);

	cudaSetDevice(0);
	cudaDeviceProp prop;
	cudaGetDeviceProperties(&prop, 0);

	uint32_t kNumSMs = prop.multiProcessorCount;
	cout<<"Number of process: "<<kNumSMs<<endl;

	cudaEventCreate(&start2);
  	cudaEventCreate(&stop2);
	cudaEventRecord(start2, 0);

	stack<Ctxt*> Vaa;
	stack<Ctxt*> Vbb;


	Stream* st = new Stream[kNumSMs];
	for (int i = 0; i < kNumSMs; i ++)
	{
		st[i].Create();
	}

	Ctxt* tmp1 = new Ctxt[MAX_FILE_LEN];
	Ctxt* tmp2 = new Ctxt[MAX_FILE_LEN];

	for(int q = timecount;q>=0;q--)
	{
		string UT = H_1(Keys, ST_temp);
		if(q==timecount)
		{
			UT_c = UT;
		}
		string C_ST = Server[UT].C_ST_C;
		// cout<<"The Search UT is: "<<UT<<endl;
		// cout<<"The Search shield code is: "<<C_ST<<endl;
		ST_temp = newxor(C_ST, H_2(Keys, ST_temp));

		Vaa.push(Server[UT].Vc);
		Vbb.push(Server[UT].Vd);

		if(C_ST=="NULL")
		{
			break;
		}
	}

	while(!Vaa.empty())
	{
		Synchronize();
		for(int i = 0; i<MAX_FILE_LEN;i++)
        {
			And(tmp1[i], Vaa.top()[i], Vbb.top()[i],st[i % kNumSMs]);
		}
		for(int i = 0; i<MAX_FILE_LEN;i++)
        {
			Not(tmp2[i], Vaa.top()[i], st[i % kNumSMs]);
		}
		for(int i = 0; i<MAX_FILE_LEN;i++)
        {
			And(Vc[i], Vc[i], tmp2[i], st[i % kNumSMs]);
		}
		for(int i = 0; i<MAX_FILE_LEN;i++)
        {
			Xor(Vc[i], Vc[i], tmp1[i], st[i % kNumSMs]);
		}
		Synchronize();
		Vaa.pop();
		Vbb.pop();
	}

	Synchronize();
	Server[UT_c].C_ST_C = "NULL";
	for(int i = 0; i<MAX_FILE_LEN;i++)
    {
		Copy(Server[UT_c].Vc[i], Vc[i], st[i % kNumSMs]);
		Copy(Server[UT_c].Vd[i], Vc[i], st[i % kNumSMs]);
	}
	Synchronize();

	cudaEventRecord(stop2, 0);
  	cudaEventSynchronize(stop2);
  	cudaEventElapsedTime(&et2, start2, stop2);

	
	cudaEventCreate(&start3);
  	cudaEventCreate(&stop3);
	cudaEventRecord(start3, 0);
	Ptxt* re1 = new Ptxt[MAX_FILE_LEN];
	for(int p = MAX_FILE_LEN-1;p>=0;p--)
	{
		Decrypt(re1[p], Vc[p], client.pri_key);
		//cout<<re1[p].message_;
	}

	cudaEventRecord(stop3, 0);
  	cudaEventSynchronize(stop3);
  	cudaEventElapsedTime(&et3, start3, stop3);


	clientsearch = et1+et3;
	serversearch = et2;
	totalsearch = clientsearch+serversearch;
	
	return;
}

 
int main() 
{
	map<string, Client> CT;
	string keyword = "dhc";    //get from erone data
    Client c;
    c.init(keyword);
	//CT[word] = c;

    unordered_map<string,CTelement> Server;
    for(int times = 0;times<MAX_TIMES;times++)   
	{
        Update(c,Server);
	}
	cout<<"The total update time is: "<<totalupdatetime<<"ms"<<endl;
	cout<<"The average update time is: "<<totalupdatetime/MAX_TIMES<<"ms"<<endl;
	Search(c,Server);
	cout<<"The client search time is: "<<clientsearch<<"ms"<<endl;
	cout<<"The server search time is: "<<serversearch/1000<<"s"<<endl;
	cout<<"The total search time is: "<<totalsearch/1000<<"s"<<endl;
	return 0;
}
