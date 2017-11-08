/* 
 *
 *     Filename: des.cpp
 *      Version: 2.0
 *  Description: Implementation of DES
 *
 *       Author: Team "Half Baked Brownies"
 *               Bishal Lama
 *               Narayan Poudel
 *               Nischal Shrestha
 *               Roshan Shrestha
 *         Date: 2017-10-30
 *
 *  Project Part 1
 *  CS 455 - Computer Security Fundamentals
 *  Instructor: Dr. Chetan Jaiswal
 *  Truman State University
 *
 */

#include <iostream>
#include <bitset>
#include <string>
#include <fstream>
#include <time.h>

using namespace std;    

const char shift_count[] = {1, 1, 2, 2, 2, 2, 2, 2};

const char IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7};

const char IP_1[] = {40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25};

const char PC_1[] = {57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4};

const char PC_2[] = {14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32};

const char E[] = {32, 1, 2, 3, 4, 5,
           4, 5, 6, 7, 8, 9,
           8, 9, 10, 11, 12, 13,
           12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21,
           20, 21, 22, 23, 24, 25,
           24, 25, 26, 27, 28, 29,
           28, 29, 30, 31, 32, 1};

const char S_BOX[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

const char P[] = {16, 7, 20, 21,
           29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2,  8, 24, 14,
           32, 27, 3, 9,
           19, 13, 30, 6,
           22, 11, 4, 25 };

// Main 64-bit key
bitset<64> key_64;
// 8 keys for 8 rounds of encryption              
bitset<48> key[8];  

//  F(R,K)
bitset < 32 > f(bitset < 32 > r, bitset < 48 > k) 
{
    bitset < 48 > exp_r;

    // Expand from 32 bits to 48 bits
    for (char i = 0; i < 48; ++i) {
        exp_r[47 - i] = r[32 - E[i]];
    }

    // ^ = XOR 
    exp_r = exp_r ^ k;

    bitset < 32 > output;
    char x = 0;

    // Decide rows and columns for the new bits
    for (char i = 0; i < 48; i += 6) {
        char row = exp_r[47 - i] * 2 +
                   exp_r[47 - i - 5];
        char col = exp_r[47 - i - 1] * 8 +
                   exp_r[47 - i - 2] * 4 +
                   exp_r[47 - i - 3] * 2 +
                   exp_r[47 - i - 4];
        char num = S_BOX[i / 6][row][col];
        bitset < 4 > bin(num);
        output[31 - x] = bin[3];
        output[31 - x - 1] = bin[2];
        output[31 - x - 2] = bin[1];
        output[31 - x - 3] = bin[0];
        x += 4;
    }

    bitset < 32 > temp = output;
    for (char i = 0; i < 32; ++i)
        output[31 - i] = temp[32 - P[i]];
    return output;
}

// Shift the key to its left by a preset count
bitset < 28 > shift_left(bitset < 28 > k, char shift) 
{
    bitset < 28 > temp = k;
    for (char i = 27; i >= 0; --i) {
        if (i - shift < 0)
            k[i] = temp[i - shift + 28];
        else
            k[i] = temp[i - shift];
    }
    return k;
}

// Generate the bitset keys that are to be used 
// for the encryption (and decrytion) processes
void key_gen() 
{
    // Named the keys after their bit numbers for 
    // easier memorization
    bitset < 56 > key_56;
    bitset < 48 > key_48;
    bitset < 28 > left;
    bitset < 28 > right;

    // Slim down 64 bits key to 56 bits
    for (char i = 0; i < 56; ++i) {
        key_56[55 - i] = key_64[64 - PC_1[i]];
    }

    // Prep 8 rounds of keys
    for (char round = 0; round < 8; ++round) {
        // Divide 56 bit key to right and left
        for (char i = 0; i < 28; ++i) {
            right[i] = key_56[i];
        }
        for (char i = 28; i < 56; ++i) {
            left[i - 28] = key_56[i];
        }

        // Shift the subkeys per their shift count
        left = shift_left(left, shift_count[round]);
        right = shift_left(right, shift_count[round]);

        for (char i = 28; i < 56; ++i) {
            key_56[i] = left[i - 28];
        }
        for (char i = 0; i < 28; ++i) {
            key_56[i] = right[i];
        }
        for (char i = 0; i < 48; ++i) {
            key_48[47 - i] = key_56[56 - PC_2[i]];
        }
        key[round] = key_48;
    }
}

// Pad the text by adding numerous x's till
// the length of the string is a factor of 8
void pad_text(string * text) 
{
    while ((( * text).length() % 8) != 0) {
        ( * text) += 'x';
    }
}

// Convert STREAMS of string to bitsets
bitset < 64 > to_bits(const char s[8]) 
{
    bitset < 64 > bits;
    for (char i = 0; i < 8; ++i)
        for (char j = 0; j < 8; ++j)
            bits[i * 8 + j] = ((s[i] >> j) & 1);
    return bits;
}

// Convert bitsets to string
string to_string(bitset < 64 > bits) 
{
    string str;
    for (char i = 0; i < 8; ++i) {
        char c = 0;
        for (char j = 7; j >= 0; j--) {
            c = c + bits[i * 8 + j];
            if (j != 0) c = c * 2;
        }
        str.push_back(c);
    }
    return str;
}

// Encrypt 64-bits at a time
bitset < 64 > encrypt(bitset < 64 > & plain) 
{
    bitset < 64 > cipher;
    bitset < 64 > new_bits;
    bitset < 32 > left;
    bitset < 32 > right;
    bitset < 32 > left_new;
    
    // Permutation
    for (char i = 0; i < 64; ++i)
        new_bits[63 - i] = plain[64 - IP[i]];
    
    // Left division
    for (char i = 32; i < 64; ++i)
        left[i - 32] = new_bits[i];
    
    // Right division
    for (char i = 0; i < 32; ++i)
        right[i] = new_bits[i];
    
    // 8 rounds of f(r,k)
    for (char round = 0; round < 8; ++round) {
        left_new = right;
        right = left ^ f(right, key[round]);
        // Set new left for the next round
        left = left_new;
    }

    // Join left and right
    for (char i = 0; i < 32; ++i)
        cipher[i] = left[i];
    for (char i = 32; i < 64; ++i)
        cipher[i] = right[i - 32];
    new_bits = cipher;

    // Permutation
    for (char i = 0; i < 64; ++i)
        cipher[63 - i] = new_bits[64 - IP_1[i]];
    
    return cipher;
}

bitset < 64 > decrypt(bitset < 64 > & cipher) 
{
    bitset < 64 > plain;
    bitset < 64 > new_bits;
    bitset < 32 > left;
    bitset < 32 > right;
    bitset < 32 > left_new;

    // Permutation
    for (char i = 0; i < 64; ++i)
        new_bits[63 - i] = cipher[64 - IP[i]];
    
    // Left division
    for (char i = 32; i < 64; ++i)
        left[i - 32] = new_bits[i];
    // Right division
    for (char i = 0; i < 32; ++i)
        right[i] = new_bits[i];

    // 8 rounds of f(r,k)    
    for (char round = 0; round < 8; ++round) {
        left_new = right;
        right = left ^ f(right, key[7 - round]);
        left = left_new;
    }

    // Join left and right
    for (char i = 0; i < 32; ++i)
        plain[i] = left[i];
    for (char i = 32; i < 64; ++i)
        plain[i] = right[i - 32];

    new_bits = plain;

    // Permutation
    for (char i = 0; i < 64; ++i)
        plain[63 - i] = new_bits[64 - IP_1[i]];
    return plain;
}

int run(string testkey)
{

    string k = testkey;

    key_64 = to_bits(k.c_str());
    key_gen();
    clock_t t1, t2;
    
    // Mode to check Encrypt or Decrypt
    char mode;
    char pad_count;

    mode = 'D';

    if (mode == 'E') {     
        cout << "\nEncrypting...\n";
        
        // Timer starts here
        t1 = clock();

        // Read the plain text file 
        ifstream ifile("plain.txt");
        string p;
        getline(ifile, p);
        ifile.close();
        pad_text( & p);
        string temp_cipher;
    
        // Encrypt the plain text 64 bits at a time
        for (int i = 0; i < p.length(); i += 8) {
            bitset < 64 > message = to_bits((p.substr(i, 8)).c_str());
            bitset < 64 > cipher = encrypt(message);
            temp_cipher += to_string(cipher);
        }
        
        ofstream ofile;
        ofile.open("encrypted.txt");
        ofile << temp_cipher;
        ofile.close();

        // Stop timer
        t2 = clock();
        float diff ((float)t2-(float)t1);
        float milliseconds = (diff / CLOCKS_PER_SEC) * 1000;

        cout << "\nEncryption successful." << 
                "\nPlease find the cipher text in encrypted.txt\n\n";

        int bitlen = p.length() * 8;
        cout << "Stats\n" << "=====\n";
        cout << "Characters count   : " << p.length() << endl;
        cout << "Bits count         : " << "64 * " << (bitlen / 64) << " bits\n";
        cout << "Encryption runtime : " << milliseconds << " ms\n\n"; 
    }  
    else if (mode == 'D') {  
        string gibberish;
        string temp_decipher;

        // Read the cipher text file
        ifstream ifile;
        ifile.open("encrypted.txt");
        getline(ifile, gibberish);
        ifile.close();

        // Take input of the cipher text 64 bits at a time
        for (int i = 0; i < gibberish.length(); i += 8) {
            bitset < 64 > gibberish_bits = to_bits((gibberish.substr(i, 8)).c_str());
            bitset < 64 > decipher = decrypt(gibberish_bits);
            temp_decipher += to_string(decipher);
        }
        ofstream ofile;
        ofile.open("decrypted.txt");
        ofile << temp_decipher;
        ofile.close();

        //cout << "\nDecrypted text: " << temp_decipher << endl << endl;
        if (temp_decipher == "brownies") {
            cout << "KEY FOUND!\n";

            return 0;
        }
    } 
    
    else 
    {
        cout << "\nInvalid input. Let's start over again.\n";
    }
    return 0;
}

void brute(int start, int end) {
    string key = "00000000";

    for (int a = start; a < end; a+=2) {
        key[0] = char(a);
        for (int b = 36; b < 128; b+=2) {
            key[1] = char(b);
            for (int c = 33; c < 128; c+=2)  {
                key[2] = char(c);
                for (int d = 33; d < 128; d+=2) {
                    key[3] = char(d);
                    for (int e = 33; e < 128; e+=2) {
                        key[4] = char(e);
                        for (int f = 33; f < 128; f+=2) {
                            key[5] = char(f);
                            for (int g = 34; g < 128; g+=2) {
                                key[6] = char(g);
                                for (int h = 34; h < 128; h+=2) {
                                    key[7] = char(h);
                                    cout << key << endl;
                                    run(key); 
                                }
                            }
                        }
                    }                   
                }
            }
        } 
    }
}

int main() 
{   
    brute(35, 36);
    return 0;
}
