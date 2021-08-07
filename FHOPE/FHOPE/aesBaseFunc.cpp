#include"aesBaseFunc.h"


/******************************下面是加密的变换函数**********************/
/**
 *  S盒变换 - 前4位为行号，后4位为列号
 */
void SubBytes(byte mtx[4 * 4])
{
	for (int i = 0; i < 16; ++i)
	{
		int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
		int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
		mtx[i] = S_Box[row][col];
	}
}

/**
 *  行变换 - 按字节循环移位
 */
void ShiftRows(byte mtx[4 * 4])
{
	// 第二行循环左移一位
	byte temp = mtx[4];
	for (int i = 0; i < 3; ++i)
		mtx[i + 4] = mtx[i + 5];
	mtx[7] = temp;
	// 第三行循环左移两位
	for (int i = 0; i < 2; ++i)
	{
		temp = mtx[i + 8];
		mtx[i + 8] = mtx[i + 10];
		mtx[i + 10] = temp;
	}
	// 第四行循环左移三位
	temp = mtx[15];
	for (int i = 3; i > 0; --i)
		mtx[i + 12] = mtx[i + 11];
	mtx[12] = temp;
}

/**
 *  有限域上的乘法 GF(2^8)
 */
byte GFMul(byte a, byte b) {
	byte p = 0;
	byte hi_bit_set;
	for (int counter = 0; counter < 8; counter++) {
		if ((b & byte(1)) != 0) {
			p ^= a;
		}
		hi_bit_set = (byte)(a & byte(0x80));
		a <<= 1;
		if (hi_bit_set != 0) {
			a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
		}
		b >>= 1;
	}
	return p;
}

/**
 *  列变换
 */
void MixColumns(byte mtx[4 * 4])
{
	byte arr[4];
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
			arr[j] = mtx[i + j * 4];

		mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];
		mtx[i + 4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];
		mtx[i + 8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);
		mtx[i + 12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);
	}
}

/**
 *  轮密钥加变换 - 将每一列与扩展密钥进行异或
 */
void AddRoundKey(byte mtx[4 * 4], word k[4])
{
	for (int i = 0; i < 4; ++i)
	{
		word k1 = k[i] >> 24;
		word k2 = (k[i] << 8) >> 24;
		word k3 = (k[i] << 16) >> 24;
		word k4 = (k[i] << 24) >> 24;

		mtx[i] = mtx[i] ^ byte(k1.to_ulong());
		mtx[i + 4] = mtx[i + 4] ^ byte(k2.to_ulong());
		mtx[i + 8] = mtx[i + 8] ^ byte(k3.to_ulong());
		mtx[i + 12] = mtx[i + 12] ^ byte(k4.to_ulong());
	}
}

/**************************下面是解密的逆变换函数***********************/
/**
 *  逆S盒变换
 */
void InvSubBytes(byte mtx[4 * 4])
{
	for (int i = 0; i < 16; ++i)
	{
		int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
		int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
		mtx[i] = Inv_S_Box[row][col];
	}
}

/**
 *  逆行变换 - 以字节为单位循环右移
 */
void InvShiftRows(byte mtx[4 * 4])
{
	// 第二行循环右移一位
	byte temp = mtx[7];
	for (int i = 3; i > 0; --i)
		mtx[i + 4] = mtx[i + 3];
	mtx[4] = temp;
	// 第三行循环右移两位
	for (int i = 0; i < 2; ++i)
	{
		temp = mtx[i + 8];
		mtx[i + 8] = mtx[i + 10];
		mtx[i + 10] = temp;
	}
	// 第四行循环右移三位
	temp = mtx[12];
	for (int i = 0; i < 3; ++i)
		mtx[i + 12] = mtx[i + 13];
	mtx[15] = temp;
}

void InvMixColumns(byte mtx[4 * 4])
{
	byte arr[4];
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
			arr[j] = mtx[i + j * 4];

		mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1])
			^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
		mtx[i + 4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1])
			^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
		mtx[i + 8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1])
			^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
		mtx[i + 12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1])
			^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
	}
}

/******************************下面是密钥扩展部分***********************/
/**
 * 将4个 byte 转换为一个 word.
 */
word Word(byte& k1, byte& k2, byte& k3, byte& k4)
{
	word result(0x00000000);
	word temp;
	temp = k1.to_ulong();  // K1
	temp <<= 24;
	result |= temp;
	temp = k2.to_ulong();  // K2
	temp <<= 16;
	result |= temp;
	temp = k3.to_ulong();  // K3
	temp <<= 8;
	result |= temp;
	temp = k4.to_ulong();  // K4
	result |= temp;
	return result;
}

/**
 *  按字节 循环左移一位
 *  即把[a0, a1, a2, a3]变成[a1, a2, a3, a0]
 */
word RotWord(word& rw)
{
	word high = rw << 8;
	word low = rw >> 24;
	return high | low;
}

/**
 *  对输入word中的每一个字节进行S-盒变换
 */
word SubWord(word& sw)
{
	word temp;
	for (int i = 0; i < 32; i += 8)
	{
		int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
		int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
		byte val = S_Box[row][col];
		for (int j = 0; j < 8; ++j)
			temp[i + j] = val[j];
	}
	return temp;
}

/**
 *  密钥扩展函数 - 对128位密钥进行扩展得到 w[4*(Nr+1)]
 */
void KeyExpansion(byte key[4 * Nk], word w[4 * (Nr + 1)])
{
	word temp;
	int i = 0;
	// w[]的前4个就是输入的key
	while (i < Nk)
	{
		w[i] = Word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
		++i;
	}

	i = Nk;

	while (i < 4 * (Nr + 1))
	{
		temp = w[i - 1]; // 记录前一个word
		if (i % Nk == 0) {
			word tmp2;
			tmp2 = RotWord(temp);
			//w[i] = w[i - Nk] ^ SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
			w[i] = w[i - Nk] ^ SubWord(tmp2) ^ Rcon[i / Nk - 1];
		}
		else
			w[i] = w[i - Nk] ^ temp;
		++i;
	}
}