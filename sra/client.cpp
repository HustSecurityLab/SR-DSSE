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
#include <unordered_map>

//The number of file
#define MAX_FILE_LEN 138724
//The number of entries
#define MAX_TIMES 109
#define Re_search 20

mpz_t modnum;
mpz_t two;

double totalupdatetime = 0;

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

//H3, used for sk
string PRF_3(string Key, int counter)
{
	string fin = Key+num2str(counter);
	string out = "";
	out = sha256(fin);
	return out;
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

//generate random str
string rand_str(const int len)
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

// Round constants for faster computation
const uint64_t keccak_RC[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

int index(int x, int y)
{
	return 5*y +x;
}

uint64_t rot64L(uint64_t ac , int l)
{
	l = l%64;
	return (ac << l) | (ac >> (64-l));
}


uint64_t rot64R(uint64_t ac , int l)
{
	l = l%64;
	return (ac >> l) | (ac << (64-l));
}

void print_state(uint64_t* A)
{
	for(int i=0; i<5; i++)
	{
		for(int j=0; j<5; j++)
			printf("%#018" PRIx64 " ", A[index(j,i)]);
		printf("\n");
	}
}

void theta(uint64_t * A)
{
	uint64_t C[5];
	for(int x=0; x<5;x++)
	{
		C[x] = A[index(x,0)] ^  A[index(x,1)] ^ A[index(x,2)] ^ A[index(x,3)] ^ A[index(x,4)];
	}

	uint64_t D[5];
	for(int x=0; x<5;x++)
	{
		D[x] = C[(x+4)%5] ^ rot64L(C[(x+1)%5],1);
	}

	for(int x=0;x<5; x++)
		for(int y=0; y<5; y++)
			A[index(x,y)] ^= D[x];
}


void rho(uint64_t * A)
{
	uint64_t Ap[25] =  {0};
	Ap[0] = A[0];

	int x = 1; int y=0;
	for(int t =0; t<=23; t++)
	{
		Ap[index(x,y)] = rot64L(A[index(x,y)],(t+1)*(t+2)/2);
		
		int yp = (2*x + 3*y) %5;
		x = y;
		y = yp;
	}
	copy(Ap, Ap +25, A);
}


void pi(uint64_t * A)
{
	uint64_t Ap[25] =  {0};
	for(int x=0; x<5; x++)
		for(int y=0; y<5; y++)
			Ap[index(x,y)] = A[index((x+3*y)%5,x)];

	copy(Ap, Ap +25, A);
}

void chi(uint64_t * A)
{
	uint64_t Ap[25] =  {0};
	for(int x=0; x<5; x++)
		for(int y=0; y<5; y++)
			Ap[index(x,y)] = A[index(x,y)] ^ ((~A[index((x+1)%5,y)]) & A[index((x+2)%5,y)]) ;

	copy(Ap, Ap +25, A);
}

uint64_t rc(int t)
{
	t = t%255;
	if(t==0)
		return 1;

	bitset<9> R(1);

	for(int i=1 ; i<= t; i++)
	{
		R <<=1;
		R[0] = R[0] ^ R[8];
		R[4] = R[4] ^ R[8];
		R[5] = R[5] ^ R[8];
		R[6] = R[6] ^ R[8];
	}
	return R[0];
}

void iota(uint64_t * A, int ir)
{
	A[0] ^= keccak_RC[ir];
}

void rnd(uint64_t * A, int ir)
{
	theta(A);
	rho(A);
	pi(A);
	chi(A);
	iota(A,ir);
}

void Keccakp(int nr, vector<u_char> &S)
{
	int l =6;
	uint64_t A[25]  = {0};
	for(int i=0; i<25; i++)
	{
		for(int j=0; j<8; j++)
		{
			A[i] += ((u_int64_t)S[8*i+j])<<(8*j);
		}
	}

	for(int ir = 12 + 2*l - nr; ir< 12 +2*l; ir++)
	{
		rnd(A,ir);
	}
	
	u_char mask = 0xff;
	for(int i=0; i<25; i++)
	{
		for(int j=0; j<8; j++)
		{
			S[8*i + j] = (A[i]>>(8*j)) & mask;
		}
	}

}

void pad0star_1(int x, int m, vector<u_char> &out)
{
	m-=4; //We already added the prefix
	int j = ((-m-2)%x+x)%x;
	int l = (j-10)/8;
	for(int k=1; k<=l;k++)
	{
		out.push_back(0);
	}
	out.push_back(0x80);
	
} 

void sponge(vector<u_char>  &N, int d_in_bytes, int r, vector<u_char>  &out)
{
	pad0star_1(r, 8 * N.size(), N);

	int n = (8*N.size())/r;
	int c = 1600-r;

	vector<u_char>  S(200,0);

	
	for(int i=0; i<n; i++)
	{
		for(int j=0; j<r/8; j++)
			S[j] ^= N[i*r/8 + j] ;
		Keccakp(24,S);
	}

	vector<u_char> Z;

	while(Z.size() < d_in_bytes)
	{
		Z.insert(Z.end(), S.begin(), S.begin() + r/8);
		Keccakp(24,S);
	}

	vector<u_char> rep(Z.begin(), Z.begin()+ d_in_bytes);
	out.clear();
	out = rep;
}


void keccak(int c, vector<u_char> &S, int d, vector<u_char> &out)
{
	sponge(S, d, 1600-c, out);
}

void shake128(vector<u_char> in, int d, vector<u_char> &out)
{
	u_char pad = 0x1f;
	in.push_back(pad);
	keccak(256, in, d, out);
}

string Shakehash(string msg, int d_in_bytes)
{
    vector<u_char> in;
	vector<u_char> out;
    for(int i = 0;i<msg.length();i++)
	{
		in.push_back(msg[i]);
	}
    shake128(in, d_in_bytes, out);
    stringstream result;
	for(int i=0; i<d_in_bytes; ++i)
    {    
        result<<std::setfill('0') << std::setw(2)<< std::hex << (int)out[i];
    }
    return result.str();
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

class CTelement
{
	public:
	string C_ST_C;
	mpz_t Va;
    mpz_t Vb;
};

class Client
{
    public:
    string ST_c;
    int counter;
	string keyword;

	string K;


    int init(string w)
    {
        counter = -1;
        string in = rand_str(10);
		string in2 = rand_str(10);

        ST_c = sha512(in2);
		K = sha256(in);

		keyword = w;

		mpz_init(modnum);
		mpz_init_set_ui(two,2);
		mpz_pow_ui(modnum,two,MAX_FILE_LEN);
        return 1;
    }
};

void Update(Client &client, unordered_map<string,CTelement> &Server)
{
	int timecount;
    double start, end,startf,endf,startt,endt;
	struct timeval t1,t2;

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


	string in = rand_str(10);

	gettimeofday(&t1,NULL);

	//Generate token
	CTelement ct;
	string ST_new = "";
    ST_new = sha512(in);

	string Keys = "";
	Keys = PRF(client.K, client.keyword);
	string Kw = Keys.substr(0, Keys.length()/2);
	string Kws = Keys.substr(Keys.length()/2, Keys.length()/2);

	client.counter++;
	string UT_new = H_1(Kw, ST_new);
	string C_ST_c = newxor(H_2(Kw, ST_new), client.ST_c);
	ct.C_ST_C = C_ST_c;

	// cout<<"UT is: "<<UT_new<<endl;
	// cout<<"C_ST is: "<<C_ST_c<<endl;
	// cout<<"The current ST is: "<<client.ST_c<<endl;

	//Encryption
	string skstr = Shakehash(PRF_3(Kws, client.counter), MAX_FILE_LEN/8);
	mpz_t sk;
	mpz_init_set_str(sk, skstr.c_str(), 16);

	mpz_init(ct.Va);
    mpz_init(ct.Vb);

	mpz_xor(ct.Va, va, sk);
	mpz_xor(ct.Vb, vb, sk);
	
	client.ST_c = ST_new;
	//cout<<"The next ST is: "<<ST_new<<endl;
	//cout<<endl;
	
	gettimeofday(&t2,NULL);

	Server[UT_new] = ct;

	totalupdatetime += (t2.tv_sec - t1.tv_sec) + (double)(t2.tv_usec - t1.tv_usec)/1000000.0;

	return;
}

void Search(Client &myclient, unordered_map<string,CTelement> &myserver)
{
	int timecount;
	double clientsearch = 0;
	double serversearch = 0;
	double totalsearch = 0;
    double start, end,startf,endf,startt,endt,starttmp;
	string in = rand_str(10);

	// int sizeofservercipher = 0;

	struct timeval t1,t2,t3,t4;

	gettimeofday(&t1,NULL);

	string Keys = "";
	Keys = PRF(myclient.K, myclient.keyword);
	string Kw = Keys.substr(0, Keys.length()/2);
	string Kws = Keys.substr(Keys.length()/2, Keys.length()/2);


	//Get current token
	string ST_temp = myclient.ST_c;
	string UT_c = "";
	int count = myclient.counter;
    mpz_t Vas[count+1],Vbs[count+1];
	int num_files = 0;

	gettimeofday(&t2,NULL);

	mpz_t result;
	mpz_init(result);

	for(int j = count; j>=0;j--)
	{
		string UT = H_1(Kw, ST_temp);
		if(j==count)
		{
			UT_c = UT;
		}
		string C_ST = myserver[UT].C_ST_C;

        mpz_init_set(Vas[j], myserver[UT].Va);
		mpz_init_set(Vbs[j], myserver[UT].Vb);
		num_files++;
		//myserver.erase(UT);

		if(C_ST=="NULL")
		{
			cout<<"break"<<endl;
			break;
		}
		string ST_cc = ST_temp;
		ST_temp = newxor(C_ST, H_2(Kw, ST_cc));
	}

	gettimeofday(&t3,NULL);

	//Client search
	mpz_t tmp1,tmp2,vaa,vbb,skaa,skbb,prev_sta;
	mpz_init(vaa);
	mpz_init(vbb);	
	mpz_init(tmp1);
	mpz_init(tmp2);
	mpz_init_set_ui(prev_sta, 0);

	int sp = count-num_files+1;
	for(int i = sp;i<=count;i++)
	{
		string key_str = Shakehash(PRF_3(Kws, i), MAX_FILE_LEN/8);
		mpz_t sk_i;
		mpz_init_set_str(sk_i, key_str.c_str(), 16);
		mpz_xor(vaa, Vas[i], sk_i);
		mpz_xor(vbb, Vbs[i], sk_i);

		mpz_and(tmp1, vaa, vbb);
		mpz_and(tmp2, vaa, prev_sta);

		mpz_xor(prev_sta, prev_sta, tmp1);
		mpz_xor(prev_sta, prev_sta, tmp2);
	}

	CTelement ct;
	string ST_new = "";
    ST_new = sha512(in);

	myclient.counter++;
	string UT_new = H_1(Kw, ST_new);
	string C_ST_c = "NULL";
	ct.C_ST_C = C_ST_c;

    string key_str = Shakehash(PRF_3(Kws, myclient.counter), MAX_FILE_LEN/8);
	mpz_t sk;
    mpz_init_set_str(sk, key_str.c_str(), 16);

	mpz_init(ct.Va);
    mpz_init(ct.Vb);

	mpz_xor(ct.Va, prev_sta, sk);
	mpz_xor(ct.Vb, prev_sta, sk);

	myclient.ST_c = ST_new;
	myserver[UT_new] = ct;

	gettimeofday(&t4,NULL);

	clientsearch=(t2.tv_sec - t1.tv_sec) + (double)(t2.tv_usec - t1.tv_usec)/1000000.0+(t4.tv_sec - t3.tv_sec) + (double)(t4.tv_usec - t3.tv_usec)/1000000.0;
	serversearch=(t3.tv_sec - t2.tv_sec) + (double)(t3.tv_usec - t2.tv_usec)/1000000.0;
	totalsearch=clientsearch+serversearch;

	cout<<"The client search: "<<clientsearch<<"s"<<endl;
	cout<<"The server search: "<<serversearch<<"s"<<endl;
	cout<<"The total search: "<<totalsearch<<"s"<<endl;

	return;
}

int main()
{
	map<string, Client> CT;
	string word = "BUYRECEIVEPOS";   //Get keyword from Erone data

    Client c;
    c.init(word);
	CT[word] = c;

	mpz_t result;
	mpz_init(result);
	unordered_map<string,CTelement> Server;

	cout<<"The word is: "<<word<<", MAX_TIME is: "<<MAX_TIMES<<endl;
	for(int times = 0;times<MAX_TIMES;times++)
	{
		Update(c, Server);
	}
	cout<<"total update: "<<totalupdatetime<<"s"<<endl;
	cout<<"Average update: "<<totalupdatetime/MAX_TIMES<<"s"<<endl;
	cout<<"****************************"<<endl;
	Search(c,Server);
	// cout<<"The first client search: "<<clientsearch<<"s"<<endl;
	// cout<<"The first server search: "<<serversearch<<"s"<<endl;
	// cout<<"The first total search: "<<totalsearch<<"s"<<endl;
	// cout<<"****************************************************************"<<endl;

	for(int times = 0;times<Re_search;times++)
	{
		Update(c, Server);
	}
	Search(c, Server);
}
