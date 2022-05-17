import math
import json
import enchant
import numpy as np
from sympy import Matrix

# read input JSON data
input_file = open(r'C:\Users\APM Z\Desktop\ComSec CW2\180405646.json')
jsondata = json.load(input_file)
input_file.close()
name = jsondata["name"]
srn = jsondata["srn"]
ciphertext = jsondata["exercise"]["intercepted"]
text = jsondata["exercise"]["text"]


def dictionaries():
    alpha = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
             'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', ' ', '-', '=']
    integer = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
               15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28]
    # text to integer pair dictionary
    text_integer = dict(zip(alpha, integer))
    # integer to text pair dictionary
    integer_text = dict(zip(integer, alpha))
    # print("my dict list", text_integer)
    # print("my dict list reverse", integer_text)
    return text_integer, integer_text


def text_to_matrix(text, text_integer):
    matrix = list(text)
    for (i, character) in enumerate(matrix):
        indexes = text_integer[character]
        matrix[i] = indexes
    return np.reshape(matrix, (3, 3)).transpose()


def matrix_to_text(matrix, order, text_integer):
    if order == 't':
        # returns a 3x3 matrix into 1-D, flattened array to transform into text
        text_array = np.ravel(matrix, order='F')
    else:
        text_array = matrix.reshape(-1)
    text = ""
    for i in range(len(text_array)):
        text = text + text_integer[text_array[i]]
    return text


def matrix_inversion(matrix):
    # checking invertibility of a matrix is there is a common factor between det(key) and base mod
    if math.gcd(int(round(np.linalg.det(matrix))), 29) == 1:
        matrix = Matrix(matrix)
        # return the inverse of matrix key (mod m) IF it exists
        return matrix.inv_mod(29)
    else:
        raise Exception("provided Matrix was not ivertible")


def hill_encryption(key, plaintext):
    # encrypt using dot product the plaintext with the key (mod 29) ==> ciphertext
    multi = np.dot(key, plaintext)
    remainder = np.remainder(
        multi, [[29, 29, 29], [29, 29, 29], [29, 29, 29]])
    return remainder.astype(int)
# numpy ndarray of object converted to scalar array of int type because during decryption, 
# this output from plaintext attack need to inverse where det() would requre same kind of input
def hill_decryption(k_inverse, c):
    return hill_encryption(k_inverse, c)


def known_plaintext_attack(c, inverse_of_p):
    return hill_encryption(c, inverse_of_p)


# MAIN DEF
def main():
    print('----- KNOWN-PLAINTEXT ATTACK \n----- KEYS FROM RESPECTIVE TEXT-CIPHERTEXT PAIRS')
    text_integer, integer_text = dictionaries()
    plaintext = text

    plaintext_matrix = text_to_matrix(plaintext, text_integer)
    inverse_of_p = matrix_inversion(plaintext_matrix)

    listed = []
    listed_keytext = []

    for i in range(0, len(ciphertext)):
        ciphers_in_matrix = text_to_matrix(
            ciphertext[i]["cipher"], text_integer)
        print('\n\nCiphertext: ', ciphertext[i]["cipher"])
    # Known-plaintext attack with the provided ciphertext - plaintext pair
        k = known_plaintext_attack(ciphers_in_matrix, inverse_of_p)
    # Convert the key matrix to a text
        key_in_text = matrix_to_text(k, "k", integer_text)

        print("Key Matrix:\n", k)
        print("Key Matrix in plaintext: ", key_in_text)

        listed.append(k)
        listed_keytext.append(key_in_text)

    print('\n\n----- HILL DECIPHER \n----- PLAINTEXTS FROM RESPECTIVE KEY-CIPHERTEXT PAIRS\n')
    k_inverses = []
    decrypted_ciphers = []
    for i in range(0, len(listed)):
        k_inverse = matrix_inversion(listed[i])
        k_inverses.append(k_inverse)  # decryption keys

    for i in range(0, len(k_inverses)):
        for j in range(0, len(ciphertext)):
            ciphers_in_matrix = text_to_matrix(
                ciphertext[j]["cipher"], text_integer)
            deciphers_in_matrix = hill_decryption(
                k_inverses[i], ciphers_in_matrix)

            plaintext = matrix_to_text(deciphers_in_matrix, "t", integer_text)
            decrypted_ciphers.append(plaintext)

    # Check if the plaintexts are english dictonary words
    isEnglishWord = enchant.Dict("en_US")

    # sliced into 5s because each key corresponds to given 5 ciphertexts
    print(
        f"Generated Plaintext from key '{listed_keytext[0]}': ", decrypted_ciphers[0:5])
    for i in decrypted_ciphers[0:5]:
        print(isEnglishWord.check(i))

    print(
        f"\nGenerated Plaintext from key '{listed_keytext[1]}': ", decrypted_ciphers[5:10])
    for i in decrypted_ciphers[5:10]:
        print(isEnglishWord.check(i))

    print(
        f"\nGenerated Plaintext from key '{listed_keytext[2]}': ", decrypted_ciphers[10:15])
    for i in decrypted_ciphers[10:15]:
        print(isEnglishWord.check(i))

    print(
        f"\nGenerated Plaintext from key '{listed_keytext[3]}': ", decrypted_ciphers[15:20])
    for i in decrypted_ciphers[15:20]:
        print(isEnglishWord.check(i))

    print(
        f"\nGenerated Plaintext from key '{listed_keytext[4]}': ", decrypted_ciphers[20:])
    for i in decrypted_ciphers[20:]:
        print(isEnglishWord.check(i))

    # write output JSON data
    # data = {
    #     "srn": srn,
    #     "name": name,
    #     "exercise": {
    #         "intercepted": [
    #             {
    #                 "cipher": ciphertext[0]["cipher"]
    #             },
    #             {
    #                 "cipher": ciphertext[1]["cipher"]
    #             },
    #             {
    #                 "cipher": ciphertext[2]["cipher"]
    #             },
    #             {
    #                 "cipher": ciphertext[3]["cipher"]
    #             },
    #             {
    #                 "cipher": ciphertext[4]["cipher"]
    #             }
    #         ],
    #         "text": text
    #     },
    #     "solution": {
    #         "key": {
    #             "encryptionKey":
    #             np.matrix(listed[0]).tolist(),
    #             "decryptionKey":
    #             np.matrix(k_inverses[0]).astype(int).tolist()
    #         },
    #         "intercepted": [
    #             {
    #                 "plain": decrypted_ciphers[0],
    #                 "cipher": ciphertext[0]["cipher"]
    #             },
    #             {
    #                 "plain": decrypted_ciphers[1],
    #                 "cipher": ciphertext[1]["cipher"]
    #             },
    #             {
    #                 "plain": decrypted_ciphers[2],
    #                 "cipher": ciphertext[2]["cipher"]
    #             },
    #             {
    #                 "plain": decrypted_ciphers[3],
    #                 "cipher": ciphertext[3]["cipher"]
    #             },
    #             {
    #                 "plain": decrypted_ciphers[4],
    #                 "cipher": ciphertext[4]["cipher"]
    #             }
    #         ]
    #     }
    # }

    # answer = json.dumps(data)

    # with open('AuntPyoneMaung_180405646_CO3326cw2.json', 'w') as jsonoutput:
    #     jsonoutput.write(answer)


if __name__ == '__main__':
    main()
