from tkinter import *
from tkinter import messagebox
from tkinter import Menu
from tkinter import ttk # Notebook/tabs widgets
import time # For creating the history / time line break.
import math # For Transpose decode.. gotta do quick maths.
import sys

version = "0.41 || 11-30-2018"

"""
To Do:
  1) DONE - Fix transpose adding in an extra carriage return at the end \n.  Maybe something to do with Tkinter getting from the message box?
    -) Make it where when using RUN button, then for each tab, it prints the === date/time === bar instead of on each function call
    -) Under selectCaesar put a check in to ensure that encrypt/decrypt cannot be set above 26.. it gives gibberish otherwise
    -) Come back to Chapter 10 (Importing file)
    -) Fix Transpose division by 0 error if spin wheel is set to 0. (ceil problem)
    --) Use spacy to have a second AND better language detection engine
    --) Add google langdetect to have a 3rd language detection engine
"""


"""
Import window building initialization
"""

window = Tk()
window.title("Version: " + str(version))
#window.geometry('800x600') # Sets the window to a hardcoded size
window.resizable(0,0) # Makes the window only as big as what all is manually displayed below

# New Notebook Trial
nb = ttk.Notebook(window)

menu = Menu(window)
menu.option_add('*tearOff', FALSE) # Global call to prevent legacy tearoff menus.

modeSelected = IntVar(None,2)

"""
Global Variables
"""
message = ''
translated = ''
key = 0
MAX_KEY_SIZE = 26

"""
Definitions
"""

"""
=================== LEGACY ===================
def getKey():
  if modeSelected.get() == 2:
    print("modeSelected == 2 == Decrypt || Setting Key = -spin.get()")
    key = -spin.get()
    return key
  elif modeSelected.get() == 1:
    print("modeSelected == 1 == Encrypt || Setting Key = spin.get()")
    key = spin.get()
    return key
  elif modeSelected.get() == 3:
    print("modeSelected == 3 == Brute || Ignoring getKey()")
  else:
    print("Bro... the getKey() is in ELSE mode.. what the fuck?")
"""

def reverseCipher(message):
  #message = inMessage.get('1.0',END)
  translated = ''
  i = len(message) - 1
  while i >= 0:
    translated = translated + message[i]
    i = i - 1
  outMessageTab1.insert('1.0', str(translated) + "\n") # Inserts in front of previous entry IN Tab!
  if isEnglish(translated):
    outMessageTab99.insert('1.0', "Reversed: " + str(translated) + "\n")
#  outMessageTab1.insert('1.0', "\n============== " + time.strftime('%m/%d/%Y %H:%M:%S') + " ============== ")

def selectCaesar():
  if modeSelected.get() == 2:
    key = -int(spin.get())
    caesarAlphabet(key)
  elif modeSelected.get() == 1:
    key = int(spin.get())
    caesarAlphabet(key)
  elif modeSelected.get() == 3:
    for key in range(1, MAX_KEY_SIZE + 1):
      caesarAlphabet(key)
  else:
    print("Caeser Didn't get a modeSelected of 1, 2, or 3.. what the FUCK are you doin'?!")

def caesarAlphabet(key):

  translated = ''
  message = inMessage.get('1.0',END).rstrip()

  for symbol in message:
    if symbol.isalpha():
      num = ord(symbol)
      num += key
      
      if symbol.isupper():
        if num > ord('Z'):
          num -= 26
        elif num < ord('A'):
          num += 26
      elif symbol.islower():
        if num > ord('z'):
          num -= 26
        elif num < ord('a'):
          num += 26
      
      translated += chr(num)
    else:
      translated += symbol
  outMessageTab2.insert('1.0', "Shift " + str(key) + ": " + str(translated) + "\n") # Inserts in front of previous entry IN Tab!
  if isEnglish(translated):
    outMessageTab99.insert('1.0', "Shifted by " + str(key) + " : " + str(translated) + "\n")
"""
LEGACY: Removed because I don't need a return for now.. I think.  and Removed the history bar to the TO DO section!
  outMessageTab2.insert('1.0', "\n============== " + time.strftime('%m/%d/%Y %H:%M:%S') + " ==============\n")
  return translated
"""

def selectASCIIRotate():
  if modeSelected.get() == 2:
    key = -int(spin.get())
    asciiRotate(key)
  elif modeSelected.get() == 1:
    key = int(spin.get())
    asciiRotate(key)
  elif modeSelected.get() == 3:
    for key in range(1, 95 + 1):
      asciiRotate(key)
  else:
    print("ASCII Rotate - How the fuck did you break this, seriously?")

def asciiRotate(key):

  translated = ''
  message = inMessage.get('1.0',END).rstrip()

  for symbol in message:
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
  outMessageTab3.insert('1.0', "Shift " + str(key) + ": " + str(translated) + "\n") # Inserts in front of previous entry IN Tab!
  if isEnglish(translated):
    outMessageTab99.insert('1.0', "Shifted by " + str(key) + " : " + str(translated) + "\n")

def selectTranspose(message):

  #message = inMessage.get('1.0',END) # Migrated message to main button run

  if modeSelected.get() == 2:
    key = int(spin.get())
    decryptTransposeCipher(key, message)
  elif modeSelected.get() == 1:
    key = int(spin.get())
    transposeCipher(key, message)
  elif modeSelected.get() == 3:
    for key in range(1, int(len(message)/2) + 1): # Transpose keys can only be up to half the length of the message.
      transposeCipher(key, message)
      decryptTransposeCipher(key, message)
  else:
    print("Transpose didn't get modeSelected of 1, 2, or 3.. what the FUCK are you doin'?!")

def transposeCipher(key, message):

  #message = inMessage.get('1.0',END).rstrip() # rstrip() To remove the trailing single \n

  # Each string in ciphertext represents a column in the grid:
  ciphertext = [''] * key
  
  # Loop through each column in ciphertext:
  for column in range(key):
    currentIndex = column

    # Keep looping until currentIndex goes past the message length.
    while currentIndex < len(message):
      # Place the character at currentIndex in message at the end of the current column in the ciphertext list
      ciphertext[column] += message[currentIndex]

      # Move currentIndex over:
      currentIndex += key

#  return ''.join(ciphertext)
  outMessageTab4.insert('1.0', "Transpose " + str(key) + ": " + str(''.join(ciphertext)) + "\n") # The join takes it from the broken up list and returns it as a clean output.

def decryptTransposeCipher(key, message):

  """
  Decryption of transposition has to simulate columns & rows of the grid that will decrypt.
  This is done by using a list of strings.
  """
  #message = inMessage.get('1.0',END).rstrip() # rstrip() To remove the trailing single \n
  
  # Calculate the number of columns, rows, and 'shaded boxes' AKA unused places at the end.
  numOfColumns = int(math.ceil(len(message) / float(key))) # Ceil is used to round up on any decimal.
  numOfRows = key
  numOfShadedBoxes = (numOfColumns * numOfRows) - len(message)
  
  # Each string in plaintext represents a column in the grid.
  plaintext = [''] * numOfColumns
  

  # The column & row variables point to where in the grid the next character in the encrypted message will go.
  column = 0
  row = 0

  for symbol in message:
    plaintext[column] += symbol
    column += 1 # Point to the next column

  # If there are no more columns OR we're at a shaded box, go back to the first column and the next row.
    if (column == numOfColumns) or (column == numOfColumns - 1 and row >= numOfRows - numOfShadedBoxes):
      column = 0
      row += 1

  joinedPlaintext = str(''.join(plaintext))
#  return ''.join(plaintext)
  outMessageTab4.insert('1.0', "Decrypted Transpose " + str(key) + ": " + str(''.join(plaintext)) + "\n") # The join takes it from the broken up list and returns it as a clean output.
  if isEnglish(joinedPlaintext):
    outMessageTab99.insert('1.0', "Decrypted Tranpose by " + str(key) + " : " + str(joinedPlaintext) + "\n")

def loadDictionaryInvent():
  dictionaryFile = open('dictionary.txt')
  englishWords = {}
  for word in dictionaryFile.read().split('\n'):
    englishWords[word] = None # This sets the key as the dictionary word but the value is None, so you can look up by key.
  dictionaryFile.close()
  return englishWords

def getEnglishCount(message):
  ENGLISH_WORDS = loadDictionaryInvent()
  message = message.upper()
  message = removeNonLetters(message)
  possibleWords = message.split()
  
  if possibleWords == []:
    return 0.0 # No words at all, return 0.0 to prevent a division error
  
  matches = 0
  for word in possibleWords:
    if word in ENGLISH_WORDS:
      matches += 1
  return float(matches) / len(possibleWords)

def removeNonLetters(message):
  UPPERLETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  LETTERS_AND_SPACE = UPPERLETTERS + UPPERLETTERS.lower() + ' \t\n'
  lettersOnly = []
  for symbol in message:
    if symbol in LETTERS_AND_SPACE:
      lettersOnly.append(symbol)
  return ''.join(lettersOnly)

def isEnglish(message, wordPercentage=20, letterPercentage=85):
  """
  The word percentage set above must exist in the dictionary file [Ex: 20% of the message's words] AND
  The letter percentage set above must be at least that percentage of the entire message's letters or spaces NOT punctuation or numbers.
  """
  wordsMatch = getEnglishCount(message) * 100 >= wordPercentage
  numLetters = len(removeNonLetters(message))
  messageLettersPercentage = float(numLetters) / len(message) * 100
  lettersMatch = messageLettersPercentage >= letterPercentage
  return wordsMatch and lettersMatch

def gcd(a,b):
  # Return the Greatest Common Divisor (GCD) aka Greatest Common Denominator
  while a != 0:
    a, b = b % a, a
  return b

def findModInverse(a,m):
  # Return the modular inverse of a % m, which is the number x, such that a*x % m = 1
  if gcd(a,m) != 1:
    return None # No mod inverse if a & m aren't relatively prime
  
  # Calculate using the EXTENDED Euclidean algorithm.
  u1, u2, u3 = 1, 0, a
  v1, v2, v3 = 0, 1, m
  while v3 != 0:
    q = u3 // v3  # The // returns a whole number (quotient) even if it would have a decimal or remainder
    v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
  return u1 & m

def getKeyParts(key):
  keyA = key // len(SYMBOLS)
  keyB = key % len(SYMBOLS)
  return (keyA, keyB)

def checkKeys(keyA, keyB, mode):
  if keyA == 1 and modeSelected.get() == 1:
    sys.exit('Cipher is weak if Key A is 1.  Choose a different key.')
  if keyB == 0 and modeSelected.get() == 1:
    sys.exit('Cipher is weak if Key B is 0.  Choose a different key.')
  if keyA < 0 or keyB < 0 or keyB > len(SYMBOLS) - 1:
    sys.exit('Key A must be greater than 0 and Key B must be between 0 and %s.' % (len(SYMBOLS) - 1))
# Pending Rest of code

def runButton():
  outMessage.delete('1.0', END) # Clears the box on each run
  message = inMessage.get('1.0', END).rstrip() # Copies exactly what is in the inMessage box.
  outMessage.insert(END, "Message: " + message) # Inserts into outMessage box whatever is got from the text copy above ^
  outMessage.insert(END, "\nMode: " + str(modeSelected.get()))
  outMessage.insert(END, "\t\tSpin: " + str(spin.get()))
  outMessage.insert(END, "\t\tMessage Length: " + str(len(message.rstrip())) + "\n")
  outMessage.insert(END, "English: " + str(isEnglish(message)) + "\n")
#  outMessageTab1.insert('1.0', "Run Button Working\n") # Just to have the button ALSO insert into a Tab
  reverseCipher(message)
  selectCaesar()
  selectTranspose(message)
  selectASCIIRotate()
  SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'


"""
Menu Creation
"""
# Create the guts of a menu list
new_item = Menu(menu)
#new_item = Menu(menu, tearoff=0) #tearoff=0 prevents you from 'removing' the menu from the window
new_item.add_command(label='New')
new_item.add_separator()
new_item.add_command(label='Edit')

# Create the 'File' menu with options from new_item
menu.add_cascade(label='File', menu=new_item)

"""
Create the widgets / labels / buttons
"""
modeLabel = Label(window, text="Choose mode: ", font=("Arial", 10))
inMessageLabel = Label(window, text="Enter text: ", font=("Arial", 8))
inMessage = Text(window, width=60, height=4, wrap=WORD)

runButton = Button(window, text="Run", width=20, command=runButton)

radEncrypt = Radiobutton(window,text='Encrypt', value=1, variable=modeSelected) #Number based variable
radDecrypt = Radiobutton(window,text='Decrypt', value=2, variable=modeSelected) #Number based variable
radBrute = Radiobutton(window,text='Brute Force', value=3, variable=modeSelected) #Number based variable

spin = Spinbox(window, from_=1, to=100, width=5)

outMessageLabel = Label(window, text="Debug: ", font=("Arial", 8))
outMessage = Text(window, width=60, height=4, wrap=WORD)

"""
Create the layout for the widgets / labels / buttons above
"""
modeLabel.grid(column=0, row=0, padx=5, sticky='W,E') # "Choose Mode: "
inMessageLabel.grid(column=0, row=1, padx=5, sticky='W') # Enter text: 
inMessage.grid(column=0, row=2, columnspan=4, padx=5, pady=(0,10)) # Actual text entered

runButton.grid(column=1, row=3, columnspan=2, pady=5) # Run

radEncrypt.grid(column=1, row=0, padx=5, sticky='W,E') # Encrypt
radDecrypt.grid(column=2, row=0, padx=5, sticky='W,E') # Decrypt
radBrute.grid(column=3, row=0, padx=5, sticky='W,E') # Brute Force

spin.grid(column=1, row=1, columnspan=2)

outMessageLabel.grid(column=0, row=4, padx=5, sticky='W') # Debug: 
outMessage.grid(column=0, row=5, columnspan=4, padx=5, pady=(0,10)) # Actual output / debug text

"""
Create the notebook AKA tabs
"""
tab1 = Frame(nb) # Reverse
tab2 = Frame(nb) # Rotate
tab3 = Frame(nb) # Full ASCII Rotate
tab4 = Frame(nb) # Transpose
tab99 = Frame(nb) # English Only Tab


nb.add(tab1,text='Reverse')
nb.add(tab2,text='Alpha Rotate')
nb.add(tab3,text='ASCII Rotate') #0x20 - 0x7E
nb.add(tab4,text='Transpose')
nb.add(tab99,text='English Results')
nb.grid(column=0, row=6, columnspan=4)

scrollbar1 = Scrollbar(tab1)
scrollbar2 = Scrollbar(tab2)
scrollbar3 = Scrollbar(tab3)
scrollbar4 = Scrollbar(tab4)
scrollbar99 = Scrollbar(tab99)


#outMessageTab1 = Text(tab1, width=60, height=4, wrap=WORD)
outMessageTab1 = Text(tab1, width=60, height=4, wrap=WORD, yscrollcommand=scrollbar1.set)
outMessageTab1.grid(row=0, column=0, sticky='W,E', columnspan=4, padx=5)
scrollbar1.grid(row=0,column=4,sticky='E,N,S')
scrollbar1.config(command=outMessageTab1.yview)

outMessageTab2 = Text(tab2, width=60, height=4, wrap=WORD, yscrollcommand=scrollbar2.set)
outMessageTab2.grid(row=0, column=0, sticky='W,E', columnspan=4, padx=5)
scrollbar2.grid(row=0,column=4,sticky='E,N,S')
scrollbar2.config(command=outMessageTab2.yview)

outMessageTab3 = Text(tab3, width=60, height=4, wrap=WORD, yscrollcommand=scrollbar3.set)
outMessageTab3.grid(row=0, column=0, sticky='W,E', columnspan=4, padx=5)
scrollbar3.grid(row=0,column=4,sticky='E,N,S')
scrollbar3.config(command=outMessageTab3.yview)

outMessageTab4 = Text(tab4, width=60, height=4, wrap=WORD, yscrollcommand=scrollbar4.set)
outMessageTab4.grid(row=0, column=0, sticky='W,E', columnspan=4, padx=5)
scrollbar4.grid(row=0,column=4,sticky='E,N,S')
scrollbar4.config(command=outMessageTab4.yview)

outMessageTab99 = Text(tab99, width=60, height=4, wrap=WORD, yscrollcommand=scrollbar99.set)
outMessageTab99.grid(row=0, column=0, sticky='W,E', columnspan=4, padx=5)
scrollbar99.grid(row=0,column=4,sticky='E,N,S')
scrollbar99.config(command=outMessageTab99.yview)

"""
Set the focus to be input, build the menu into the window, and finally show window on loop.
"""
inMessage.focus() # Sets the main windows focus to be on this initially

window.config(menu=menu)
window.mainloop()