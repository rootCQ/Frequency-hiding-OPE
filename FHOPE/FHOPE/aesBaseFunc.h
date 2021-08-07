#pragma once
#include"aesData.h"

const int Nr = 10;  // AES需要 10 轮加密
const int Nk = 4;   // Nk 表示输入密钥的 word 个数

/******************************下面是加密的变换函数**********************/

void SubBytes(byte mtx[4 * 4]);// S盒变换 - 前4位为行号，后4位为列号

void ShiftRows(byte mtx[4 * 4]);//行变换 - 按字节循环移位

byte GFMul(byte a, byte b);//有限域上的乘法 GF(2^8)

void MixColumns(byte mtx[4 * 4]);//列变换

void AddRoundKey(byte mtx[4 * 4], word k[4]);//轮密钥加变换 - 将每一列与扩展密钥进行异或

/**************************下面是解密的逆变换函数***********************/

void InvSubBytes(byte mtx[4 * 4]);//逆S盒变换

void InvShiftRows(byte mtx[4 * 4]);//逆行变换 - 以字节为单位循环右移

void InvMixColumns(byte mtx[4 * 4]);

/******************************下面是密钥扩展部分***********************/

word Word(byte& k1, byte& k2, byte& k3, byte& k4);//将4个 byte 转换为一个 word.

word RotWord(word& rw);//按字节 循环左移一位,即把[a0, a1, a2, a3]变成[a1, a2, a3, a0]

word SubWord(word& sw);//对输入word中的每一个字节进行S-盒变换

void KeyExpansion(byte key[4 * Nk], word w[4 * (Nr + 1)]);//密钥扩展函数 - 对128位密钥进行扩展得到 w[4*(Nr+1)]