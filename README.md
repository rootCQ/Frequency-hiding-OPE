# Frequency-hiding OPE
Self-designed frequency-hiding order preserving encryption for 2019 Chinese Cryptographic Competition.

### OPE

**Order-Preserving Encryption** is a scheme that keeps the order of plain text preserved after the encryption, allowing server to compare and search within a range without decryption.

### Algorithm Framework

In the client endpoint, the *keycnt* is needed for storing occurring and updating times of each plaintext. In the server endpoint, a B+ tree is built for order recording purpose.

The framework of algorithm is as follows:
![image](https://user-images.githubusercontent.com/40510114/128590500-fa00aaef-1c20-4b87-a049-48618ddfba87.png)

***keycnt***  is the storage of data with its times of occurrence and updating.
![image](https://user-images.githubusercontent.com/40510114/128590870-d6f85c4d-e87b-4f44-b8c4-7b5f453323cf.png)

***B+\* tree*** is different with the typical type. The cyphers are in leaf nodes only, linked with one another as list. The rest of nodes keep the number of its child leaf nodes.
![image](https://user-images.githubusercontent.com/40510114/128590878-29367781-ee9b-48ec-9a54-c133486ba505.png)
