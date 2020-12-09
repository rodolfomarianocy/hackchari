from itertools import product
from sys import exit

def Generateword(key, caracteres, min, max):
    try:
        print(type(key))
        print(key)
        file = 'wordlist.txt'
        i = file
        if int(min) > int(max) or caracteres is None or file is None:
            exit()
        with open(file, 'w') as arquivo:
            caracteres = list(str(caracteres))

            print('\n[*] Generating wordlist ...\n')

            for i in range(int(min),int(max)+1):
                for j in product(caracteres,repeat=i):
                    word = ''.join(j)
                    arquivo.write('%s\n' %word)
    except KeyboardInterrupt:
        exit(1)

if __name__ == "__main__":
    Generateword()