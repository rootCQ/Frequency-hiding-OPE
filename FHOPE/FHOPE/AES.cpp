#include <iostream>
#include <string>
#include"encrypt.h"
#include"decrypt.h"

using namespace std;

int main()
{
	byte key[16] = { 0x2b, 0x7e, 0x15, 0x16,
					0x28, 0xae, 0xd2, 0xa6,
					0xab, 0xf7, 0x15, 0x88,
					0x09, 0xcf, 0x4f, 0x3c };

	byte plain[16] = { 0x32, 0x88, 0x31, 0xe0,
					0x43, 0x5a, 0x31, 0x37,
					0xf6, 0x30, 0x98, 0x07,
					0xa8, 0x8d, 0xa2, 0x34 };
	// �����Կ
	cout << "��Կ�ǣ�";
	for (int i = 0; i < 16; ++i)
		cout << hex << key[i].to_ulong() << " ";
	cout << endl;
	


	word w[4 * (Nr + 1)];
	KeyExpansion(key, w);

	// ��������ܵ�����
	cout << endl << "�����ܵ����ģ�" << endl;
	for (int i = 0; i < 16; ++i)
	{
		cout << hex << plain[i].to_ulong() << " ";
		if ((i + 1) % 4 == 0)
			cout << endl;
	}
	cout << endl;

	// ���ܣ��������
	encrypt(plain, w);
	cout << "���ܺ�����ģ�" << endl;
	for (int i = 0; i < 16; ++i)
	{
		cout << hex << plain[i].to_ulong() << " ";
		if ((i + 1) % 4 == 0)
			cout << endl;
	}
	cout << endl;

	// ���ܣ��������
	decrypt(plain, w);
	cout << "���ܺ�����ģ�" << endl;
	for (int i = 0; i < 16; ++i)
	{
		cout << hex << plain[i].to_ulong() << " ";
		if ((i + 1) % 4 == 0)
			cout << endl;
	}
	cout << endl;
	return 0;
}
