#pragma once
#include"aesData.h"

const int Nr = 10;  // AES��Ҫ 10 �ּ���
const int Nk = 4;   // Nk ��ʾ������Կ�� word ����

/******************************�����Ǽ��ܵı任����**********************/

void SubBytes(byte mtx[4 * 4]);// S�б任 - ǰ4λΪ�кţ���4λΪ�к�

void ShiftRows(byte mtx[4 * 4]);//�б任 - ���ֽ�ѭ����λ

byte GFMul(byte a, byte b);//�������ϵĳ˷� GF(2^8)

void MixColumns(byte mtx[4 * 4]);//�б任

void AddRoundKey(byte mtx[4 * 4], word k[4]);//����Կ�ӱ任 - ��ÿһ������չ��Կ�������

/**************************�����ǽ��ܵ���任����***********************/

void InvSubBytes(byte mtx[4 * 4]);//��S�б任

void InvShiftRows(byte mtx[4 * 4]);//���б任 - ���ֽ�Ϊ��λѭ������

void InvMixColumns(byte mtx[4 * 4]);

/******************************��������Կ��չ����***********************/

word Word(byte& k1, byte& k2, byte& k3, byte& k4);//��4�� byte ת��Ϊһ�� word.

word RotWord(word& rw);//���ֽ� ѭ������һλ,����[a0, a1, a2, a3]���[a1, a2, a3, a0]

word SubWord(word& sw);//������word�е�ÿһ���ֽڽ���S-�б任

void KeyExpansion(byte key[4 * Nk], word w[4 * (Nr + 1)]);//��Կ��չ���� - ��128λ��Կ������չ�õ� w[4*(Nr+1)]