from os import urandom
from random import choice

char_set = {'small': b'abcdefghijklmnopqrstuvwxyz',
             'nums': b'0123456789',
             'big': b'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
             'special': b'!-_.'
            }

def generate_pass(length=21):
    """Function to generate a password"""

    password = []

    while len(password) < length:
        key = choice(list(char_set.keys()))
        a_char = urandom(1)
        if a_char in char_set[key]:
            if check_prev_char(password, char_set[key]):
                continue
            else:
                password.append(a_char)
    return b''.join(password).decode('utf-8')


def check_prev_char(password, current_char_set):
    """Function to ensure that there are no consecutive 
    UPPERCASE/lowercase/numbers/special-characters."""

    index = len(password)
    if index == 0:
        return False
    else:
        prev_char = password[index - 1]
        if prev_char in current_char_set:
            return True
        else:
            return False

if __name__ == '__main__':
    print(generate_pass())
