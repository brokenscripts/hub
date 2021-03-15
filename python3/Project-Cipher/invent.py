class Invent(object):
    """
    Ensure you instantiate this class prior to using.
    checklang = Invent()   checklang.isEnglish('words')
    """
    def __init__(self):
        """Return a new English Check object."""
        self.dictionaryFile = open('dictionary.txt')
        self.englishWords = {}
        for word in self.dictionaryFile.read().split('\n'):
            self.englishWords[word] = None  # Dict Key = Word, Value = None, for fast lookup
        self.dictionaryFile.close()
        #  return englishWords

    def getEnglishCount(self, message):
        message = message.upper()
        message = self.removeNonLetters(message)
        possibleWords = message.split()

        if possibleWords == []:
            return 0.0  # No words at all, return 0.0 to prevent a division error

        matches = 0
        for word in possibleWords:
            if word in self.englishWords:
                matches += 1
        return float(matches) / len(possibleWords)

    def removeNonLetters(self, message):
        UPPERLETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        LETTERS_AND_SPACE = UPPERLETTERS + UPPERLETTERS.lower() + ' \t\n'
        lettersOnly = []
        for symbol in message:
            if symbol in LETTERS_AND_SPACE:
                lettersOnly.append(symbol)
        return ''.join(lettersOnly)

    def isEnglish(self, message, wordPercentage=20, letterPercentage=85):
        """
        The word % set above must exist in the dictionary file [Ex: 20% of the message's words] AND
        The letter % set above must be at least that % of the entire message's letters or spaces NOT punctuation or #s.
        """
        wordsMatch = self.getEnglishCount(message) * 100 >= wordPercentage
        numLetters = len(self.removeNonLetters(message))
        messageLettersPercentage = float(numLetters) / len(message) * 100
        lettersMatch = messageLettersPercentage >= letterPercentage
        return wordsMatch and lettersMatch
