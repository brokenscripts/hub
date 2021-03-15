from abc import ABCMeta, abstractmethod
from invent import Invent  # Invent with Python's English language checker
import math  # Used in Transpose decode.. gotta do quick maths.
import sys
import random  # Used in Substitution
import re
import copy  # Used in Substitution
import wordPatterns
import makeWordPatterns

# TODO: Make the classes accept a message OR be able to set self.message from the encode/decode functions directly

# TODO: Fix Substitute so it can be called directly and apply the message from function
# TODO: Convert Transpose listing to Dictionary so it shows the key length?
# TODO: Add Affine
# TODO: Add Vigenere
# TODO: Add Frequency Analysis

"""
Note using f-strings, required Python 3.6+ (Only in use on __str__ on Cipher class, currently)

Setup:
mylang = Invent()
r = Reverse("dog") # Prints god via __repr__ calling the function
r = Rotate("yeah") | ASCIIRotate | Transpose
  r.encode(3) # Rotates +3 and returns the value (shows on screen).
  for i in r.brute():
    if mylang.isEnglish(i) == True:  # Only show valid english results.
      print(i)
"""


class Cipher(object):
    """
    Learning from: https://jeffknupp.com/blog/2014/06/18/improve-your-python-python-classes-and-object-oriented-programming/
    More information on classes: https://python-textbok.readthedocs.io/en/1.0/Classes.html
    Fixing the follow on classes: https://www.python-course.eu/python3_inheritance.php
      ### Still do not understand why I have to init twice inside my reverse class

    An attempt at making a Cipher class

    Attributes:
        message: A string input to encode/decode
        key: a number to move/shift/rotate
        symbols: Alphabet to use, can be [a-z][A-Z][0-9] or any ascii symbol depending on encoding
    """

    __metaclass__ = ABCMeta

    key = 0
    symbols = ''

    def __init__(self, message):
        """Return a new cipher object."""
        self.message = message

    def __str__(self):
        """Pretty print everything that we fed the main Cipher class"""
        return f'Message: {self.message} **Note: This is the __str__ method from Cipher super class.'

    @abstractmethod
    def cipher_type(self):
        """Return a string representing the type of cipher this is."""
        pass


class Reverse(Cipher):
    """
    Reverse cipher
    Ways to use:
    r = Reverse("yeah") # Able to print(r) to see what all went into it since it inherits from Cipher class
    r = Reverse.backwards("yeah") # This sets r to the returned string - show with: print(r)
    Reverse.backwards("yeah") # This returns the reversed value to the function & displays it in terminal
    print(Reverse.backwards("yeah")) #### Does this need to be done since I can do the one above?
    r.cipher_type() # This displays the string "reverse" just for shits n giggles
    """

    def __init__(self, message):
        Cipher.__init__(self, message)

    def __repr__(self):
        """Debug maybe?"""
        return Reverse.backwards(self)

    def backwards(self):
        translated = ''

        i = len(self.message) - 1
        while i >= 0:
            translated = translated + self.message[i]
            i = i - 1

        return translated

    def cipher_type(self):
        """Return a string representing the type of cipher this is."""
        return 'reverse'


class Rotate(Cipher):
    """
    Rotate cipher
    """

    SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

    def __init__(self, message=None):
        Cipher.__init__(self, message)

    def rotate(self, message, key):
        translated = ''

        for symbol in self.message:
            if symbol in self.SYMBOLS:
                symbolIndex = self.SYMBOLS.find(symbol)

                translatedIndex = symbolIndex + key
                if translatedIndex >= len(self.SYMBOLS):
                    translatedIndex = translatedIndex - len(self.SYMBOLS)
                elif translatedIndex < 0:
                    translatedIndex = translatedIndex + len(self.SYMBOLS)

                translated = translated + self.SYMBOLS[translatedIndex]
            else:
                translated = translated + symbol

        return translated

    def brute(self, message=None):
        """ Rotate class, brute (All possible combinations).
        r = Rotate('message').  r.brute()
        mine = r.brute()
        mylang = Invent()
        for key,val in mine.items():    # Items gives both.  There is values and keys as well.
            if mylang.isEnglish(val):
                print(key,val)
        """
        # brutelist = []  # Switched to Dict to show rotation number.
        brutelist = {}
        if message is not None:
            self.message = message
        for key in range(len(self.SYMBOLS)):
            brutelist[key] = self.rotate(self, key)
            #  brutelist.append(self.rotate(self, key)) # Switched to Dict to show rotation number.
        return brutelist
        # yield self.rotate(self, key)
        # print(self.rotate(self, key))

    def decode(self, key=None, message=None):
        """ Rotate class, decode (Negative Shift).  r = Rotate('message').  r.decode(3) """
        if key is not None:
            if message is not None:
                self.message = message
            key = -key
            return self.rotate(self, key)
        else:
            print("decode was called without a key")

    def encode(self, key=None, message=None):
        """ Rotate class, encode (Positive Shift).  r = Rotate('message').  r.encode(3) """
        if key is not None:
            if message is not None:
                self.message = message
            return self.rotate(self, key)
        else:
            print("encode was called without a key")

    def cipher_type(self):
        """ Return a string representing the type of cipher this is. """
        return 'rotate'


class ASCIIRotate(Cipher):
    """
    ASCII Rotation cipher
    """

    def __init__(self, message=None):
        Cipher.__init__(self, message)

    def rotate(self, message, key):
        translated = ''

        for symbol in self.message:
            if symbol.isascii():
                num = ord(symbol)
                num += key

                if num > ord('~'):
                    num -= 95
                elif num < ord(' '):
                    num += 95

                translated += chr(num)
            else:
                translated += symbol

        return translated

    def brute(self, message=None):
        """ ASCIIRotate class, brute (All possible combinations).
        r = ASCIIRotate('message').  r.brute(). Print cleanly with print('\n'.join(r.brute())) """
        brutelist = {}
        if message is not None:
            self.message = message
        for key in range(1, 96):
            brutelist[key] = self.rotate(self, key)
        return brutelist

    def decode(self, key=None, message=None):
        """ ASCIIRotate class, decode (Negative Shift).  r = ASCIIRotate('message').  r.decode(3) """
        if key is not None:
            if message is not None:
                self.message = message
            key = -key
            return self.rotate(self, key)
        else:
            print("decode was called without a key")

    def encode(self, key=None, message=None):
        """ ASCIIRotate class, encode (Positive Shift).  r = ASCIIRotate('message').  r.encode(3) """
        if key is not None:
            if message is not None:
                self.message = message
            return self.rotate(self, key)
        else:
            print("encode was called without a key")

    def cipher_type(self):
        """ Return a string representing the type of cipher this is. """
        return 'ASCII Rotate'


class Transpose(Cipher):
    """
    Transposition cipher
    """

    def __init__(self, message=None):
        Cipher.__init__(self, message)

    def encode(self, key=None, message=None):
        if key is not None:
            if message is not None:
                self.message = message
            # Each string in ciphertext represents a column in the grid:
            ciphertext = [''] * key

            # Loop through each column in ciphertext:
            for column in range(key):
                currentIndex = column

                # Keep looping until currentIndex goes past the message length.
                while currentIndex < len(self.message):
                    # Place the char at currentIndex in message at the end of the current column in the ciphertext list
                    ciphertext[column] += self.message[currentIndex]

                    # Move currentIndex over:
                    currentIndex += key

            return ''.join(ciphertext)
        else:
            print("encode was called without a key")

    def decode(self, key=None, message=None):
        if key is not None:
            if message is not None:
                self.message = message

            # Calculate the number of columns, rows, and 'shaded boxes' AKA unused places at the end.
            numOfColumns = int(math.ceil(len(self.message) / float(key)))  # Ceil is used to round up on any decimal.
            numOfRows = key
            numOfShadedBoxes = (numOfColumns * numOfRows) - len(self.message)

            # Each string in plaintext represents a column in the grid.
            plaintext = [''] * numOfColumns

            # The column & row variables point to where in the grid the next character in the encrypted message will go.
            column = 0
            row = 0

            for symbol in self.message:
                plaintext[column] += symbol
                column += 1  # Point to the next column

                # If there are no more columns OR we're at a shaded box, go back to the first column and the next row.
                if (column == numOfColumns) or (column == numOfColumns - 1 and row >= numOfRows - numOfShadedBoxes):
                    column = 0
                    row += 1

            joinedPlaintext = str(''.join(plaintext))
            return joinedPlaintext
        else:
            print("decode was called without a key")

    def brute(self, message=None):
        """ Transpose class, brute (All possible combinations).
        r = Transpose('message').  r.brute(). This will return 2 lists, encodebrutelist and decodebrutelist
        Transpose keys can only be up to HALF the length of the message.
        """
        encodebrutelist = []
        decodebrutelist = []

        if message is not None:
            self.message = message
        for key in range(1, int(len(self.message) / 2) + 1):
            encodebrutelist.append(self.encode(key))
            decodebrutelist.append(self.decode(key))
        return encodebrutelist, decodebrutelist

    def cipher_type(self):
        """ Return a string representing the type of cipher this is. """
        return 'transpose'


class Substitute(Cipher):
    """
    Substitution cipher
    """

    LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    nonLettersOrSpacePattern = re.compile('[^A-Z\s]')

    def __init__(self, message=None):
        Cipher.__init__(self, message)
        if message is not None:
            self.message = message

    def keyIsValid(self, key):
        keyList = list(key)
        lettersList = list(self.LETTERS)
        keyList.sort()
        lettersList.sort()

        return keyList == lettersList

    def getRandomKey(self):
        key = list(self.LETTERS)
        random.shuffle(key)
        return ''.join(key)

    def keywordAlphabet(self, keyword):
        # create the key from the keyword
        newKey = ''
        keyword = keyword.upper()
        keyAlphabet = list(self.LETTERS)
        for i in range(len(keyword)):
            if keyword[i] not in newKey:
                newKey += keyword[i]
                keyAlphabet.remove(keyword[i])
        key = newKey + ''.join(keyAlphabet)
        return key

    def translateMessage(self, message, key, A, B):
        translated = ''
        """
        For Encrypt, define A = self.letters, B = key
        For Decrypt, swap them, define A = key, B = self.letters
        """
        charsA = A
        charsB = B

        # Loop through each symbol in the message:
        for symbol in self.message:
            if symbol.upper() in charsA:
                # Encrypt/decrypt the symbol:
                symIndex = charsA.find(symbol.upper())
                if symbol.isupper():
                    translated += charsB[symIndex].upper()
                else:
                    translated += charsB[symIndex].lower()
            else:
                # Symbol is not in LETTERS; just add it:
                translated += symbol

        return translated

    def encode(self, key=None):
        """
        Substitute class, encode defaults to random key unless specified
        s = Substitute('Long message')
        s.encode() # Will return encoded message and print random key (monolithic alphabet) used
        s.encode('UJBNVTPWXHSLECGRQIYMFZAODK') will use this key instead of random, and outputs 'Lgcp evyyupv'
        """
        if key is not None:
            return self.translateMessage(self, key, self.LETTERS, key)
        else:
            key = self.getRandomKey()
            print("Encoding using random key generated: " + str(key))
            return self.translateMessage(self, key, self.LETTERS, key)

    def decode(self, key=None):
        """
        Substitute class, decode defaults to random key unless specified
        s = Substitute('Long message')
        s.decode() # Will try a random key generated -- This has basically NO chance of working.
        s.decode('LFWOAYUISVKMNXPBDCRJTQEGHZ') will use this key to decode the message
        """
        if key is not None:
            return self.translateMessage(self, key, key, self.LETTERS)
        else:
            key = self.getRandomKey()
            print("Attempting to decode using random key generated: " + str(key))
            return self.translateMessage(self, key, key, self.LETTERS)

    def getWordPattern(self, word):
        # Returns a string of the pattern form of the given word.
        # e.g. '0.1.2.3.4.1.2.3.5.6' for 'DUSTBUSTER'
        word = word.upper()
        nextNum = 0
        letterNums = {}
        wordPattern = []

        for letter in word:
            if letter not in letterNums:
                letterNums[letter] = str(nextNum)
                nextNum += 1
            wordPattern.append(letterNums[letter])
        return '.'.join(wordPattern)

    def getBlankCipherletterMapping(self):
        # Returns a dictionary value that is a blank cipher letter mapping.
        return {'A': [], 'B': [], 'C': [], 'D': [], 'E': [], 'F': [], 'G': [], 'H': [], 'I': [], 'J': [], 'K': [],
                'L': [], 'M': [], 'N': [], 'O': [], 'P': [], 'Q': [], 'R': [], 'S': [], 'T': [], 'U': [], 'V': [],
                'W': [], 'X': [], 'Y': [], 'Z': []}

    def addLettersToMapping(self, letterMapping, cipherword, candidate):
        """
        The `letterMapping` parameter is a "cipher letter mapping" dictionary
        value that the return value of this function starts as a copy of.
        The `cipherword` parameter is a string value of the ciphertext word.
        The `candidate` parameter is a possible English word that the
        cipherword could decrypt to.

        This function adds the letters of the candidate as potential
        decryption letters for the cipherletters in the cipherletter
        mapping.
        """
        for i in range(len(cipherword)):
            if candidate[i] not in letterMapping[cipherword[i]]:
                letterMapping[cipherword[i]].append(candidate[i])

    def intersectMappings(self, mapA, mapB):
        # To intersect two maps, create a blank map, and then add only the
        # potential decryption letters if they exist in BOTH maps.
        intersectedMapping = self.getBlankCipherletterMapping()
        for letter in self.LETTERS:

            # An empty list means "any letter is possible". In this case just
            # copy the other map entirely.
            if mapA[letter] == []:
                intersectedMapping[letter] = copy.deepcopy(mapB[letter])
            elif mapB[letter] == []:
                intersectedMapping[letter] = copy.deepcopy(mapA[letter])
            else:
                # If a letter in mapA[letter] exists in mapB[letter], add
                # that letter to intersectedMapping[letter].
                for mappedLetter in mapA[letter]:
                    if mappedLetter in mapB[letter]:
                        intersectedMapping[letter].append(mappedLetter)

        return intersectedMapping

    def removeSolvedLettersFromMapping(self, letterMapping):
        # Cipherletters in the mapping that map to only one letter are
        # "solved" and can be removed from the other letters.
        # For example, if 'A' maps to potential letters ['M', 'N'], and 'B'
        # maps to ['N'], then we know that 'B' must map to 'N', so we can
        # remove 'N' from the list of what 'A' could map to. So 'A' then maps
        # to ['M']. Note that now that 'A' maps to only one letter, we can
        # remove 'M' from the list of letters for every other
        # letter. (This is why there is a loop that keeps reducing the map.)

        loopAgain = True
        while loopAgain:
            # First assume that we will not loop again:
            loopAgain = False

            # `solvedLetters` will be a list of uppercase letters that have one
            # and only one possible mapping in `letterMapping`:
            solvedLetters = []
            for cipherletter in self.LETTERS:
                if len(letterMapping[cipherletter]) == 1:
                    solvedLetters.append(letterMapping[cipherletter][0])

            # If a letter is solved, than it cannot possibly be a potential
            # decryption letter for a different ciphertext letter, so we
            # should remove it from those other lists:
            for cipherletter in self.LETTERS:
                for s in solvedLetters:
                    if len(letterMapping[cipherletter]) != 1 and s in letterMapping[cipherletter]:
                        letterMapping[cipherletter].remove(s)
                        if len(letterMapping[cipherletter]) == 1:
                            # A new letter is now solved, so loop again.
                            loopAgain = True
        return letterMapping

    def hackSimpleSub(self, message):
        # message is called via brute.  It is used even though IDE says it isn't
        intersectedMap = self.getBlankCipherletterMapping()
        cipherwordList = self.nonLettersOrSpacePattern.sub('', self.message.upper()).split()
        for cipherword in cipherwordList:
            # Get a new cipherletter mapping for each ciphertext word:
            candidateMap = self.getBlankCipherletterMapping()

            wordPattern = self.getWordPattern(cipherword)
            if wordPattern not in wordPatterns.allPatterns:
                continue  # This word was not in our dictionary, so continue.

            # Add the letters of each candidate to the mapping:
            for candidate in wordPatterns.allPatterns[wordPattern]:
                self.addLettersToMapping(candidateMap, cipherword, candidate)

            # Intersect the new mapping with the existing intersected mapping:
            intersectedMap = self.intersectMappings(intersectedMap, candidateMap)

        # Remove any solved letters from the other lists:
        return self.removeSolvedLettersFromMapping(intersectedMap)

    def brute(self):
        """
        Substitute class, brute force method
        s = Substitute('Lgcp evyyupv')
        s.brute() # Using word patterns will attempt to solve, short messages will most likely fail.
        TODO: Add in other python methods to solve brute force to include short messages and english check
        """
        letterMapping = self.hackSimpleSub(self)
        # Return a string of the ciphertext decrypted with the letter mapping,
        # with any ambiguous decrypted letters replaced with an _ underscore.

        # First create a simple sub key from the letterMapping mapping:
        key = ['x'] * len(self.LETTERS)
        for cipherletter in self.LETTERS:
            if len(letterMapping[cipherletter]) == 1:
                # If there's only one letter, add it to the key.
                keyIndex = self.LETTERS.find(letterMapping[cipherletter][0])
                key[keyIndex] = cipherletter
            else:
                self.message = self.message.replace(cipherletter.lower(), '_')
                self.message = self.message.replace(cipherletter.upper(), '_')
        key = ''.join(key)

        print("Overwriting original ciphertext, Brute Force best guess: " + str(key))

        return self.decode(key)

    def brutedict(self):
        SILENT_MODE = False
        mylang = Invent()
        ENGLISH_WORDS = mylang.englishWords
        print('Hacking with %s possible dictionary words...' % (len(ENGLISH_WORDS) * 3))

        # Python programs can be stopped at any time by pressing Ctrl-C (on Windows) or Ctrl-D (on Mac and Linux)
        print('(Press Ctrl-C or Ctrl-D to quit at any time.)')

        tryNum = 1

        # brute-force by looping through every possible key
        for key in ENGLISH_WORDS:
            if tryNum % 100 == 0 and not SILENT_MODE:
                print('%s keys tried. (%s)' % (tryNum, key))

            decryptedText = self.decode(self.keywordAlphabet(key))

            if mylang.getEnglishCount(decryptedText) > 0.20:
                # Check with the user to see if the decrypted key has been found.
                print()
                print('Possible encryption hack:')
                print('Key: ' + str(key))
                print('Decrypted message: ' + decryptedText[:100])
                print()
                print('Enter D for done, or just press Enter to continue hacking:')
                response = input('> ')

                if response.upper().startswith('D'):
                    return decryptedText

            tryNum += 1
        return None

    def cipher_type(self):
        """ Return a string representing the type of cipher this is. """
        return 'substitution'


class Morse(Cipher):
    """
    Morse Code cipher
    """

    def __init__(self, message=None):
        Cipher.__init__(self, message)
        self.CODE = {'A': '.-', 'B': '-...', 'C': '-.-.',
                     'D': '-..', 'E': '.', 'F': '..-.',
                     'G': '--.', 'H': '....', 'I': '..',
                     'J': '.---', 'K': '-.-', 'L': '.-..',
                     'M': '--', 'N': '-.', 'O': '---',
                     'P': '.--.', 'Q': '--.-', 'R': '.-.',
                     'S': '...', 'T': '-', 'U': '..-',
                     'V': '...-', 'W': '.--', 'X': '-..-',
                     'Y': '-.--', 'Z': '--..',

                     '0': '-----', '1': '.----', '2': '..---',
                     '3': '...--', '4': '....-', '5': '.....',
                     '6': '-....', '7': '--...', '8': '---..',
                     '9': '----.', '?': '----', ' ': ' '
                     }

        self.CODE_REVERSED = {value: key for key, value in self.CODE.items()}
        # Mapping is Alpha to Morse
        # Dictionary Comprehension is Morse to Alpha

    def encode(self, message=None):  # Mapping
        """ Morse code class, encode m = Morse("Hello"). m.encode()"""
        if message is not None:
            self.message = message
        return ' '.join(self.CODE.get(i.upper()) for i in self.message)

    def decode(self, message=None):  # Dictionary Comprehension
        """ Morse code class, m = Morse("'.... . .-.. .-.. ---'").  m.decode()"""
        if message is not None:
            self.message = message
        return ''.join(self.CODE_REVERSED.get(i) for i in self.message.split())

    def flip(self, message=None):
        if message is not None:
            self.message = message
        morseorig = ".-"
        morseflip = "-."
        flipcode = self.message.maketrans(morseorig, morseflip)
        return self.message.translate(flipcode)

    def cipher_type(self):
        """ Return a string representing the type of cipher this is. """
        return 'morse'
