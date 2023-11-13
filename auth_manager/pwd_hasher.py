from sys import argv
from argon2 import PasswordHasher

if __name__ == "__main__":
    print(PasswordHasher().hash(argv[1]))