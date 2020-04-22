#!/usr/bin/env python
# coding: utf-8

# Exported from Jupyter Notebook

# Substitution function
def sub(text, _map):
    newText = ""
    for l in text:
        try:
            newText += _map[l]
        except KeyError:
            newText += l
    return newText

# Encoded text
encoded = "d xsf xnsydoi zojk fvzycf sou s jzoi fjnnwnu c fvdyc. d vsu rk rdlys yzqe fvznf zo rk tnnc, sou rk qvsje gsi usoijdoi sc rk gsqe, glc oz vsyonff, sou ozc nwno s fdoijn qsysgdony. do zon hzqenc d hlc s tnx qjdt edu bgsyf, rk tswzydcn rljcd hdcqv fosqe, sou d tdjjnu s qzjjshfdgjn tjsfe xdcv sgzlc s cvdyu zt s jdcny zt xscny. d hlc cvsc do rk zcvny hzqenc, cvzliv dc hljjnu rk fvzycf uzxo s jdccjn. glc d eonx dc xzlju csen rn s tnx vzlyf cz qjdrg cvn yzlcn, sou d udu ozc xsoc cz gn hsyqvnu gk cvn cdrn d ynsqvnu cvn vsyu hdcqvnf lh vdiv. s hsqe xsf zlc zt cvn plnfcdzo, hsycjk gnqslfn zt sjj cvn qvdronkf do cvn rduujn zt cvn yzlcn, glc rsdojk gnqslfn cvn qjdrgdoi xsf vsyu nozliv cvsc d udu ozc xsoc sok nmcys xndivc zo rk gzuk."
encoded

# Mapping alphabet
mapTo = {
    'd':'I', # Guess that sentence starts at i
    's':'A', # a lot of single 's', replace to 'a' since its most common single letter
    'j':'L', # 'Ajj' in the last sentence could be mapped to 'ALL' only
    'c':'T', # 'Ac' in the second sentence could be only 'an', 'at', 'as'
    'v':'H', # 'TvAT' in the last sentence in obviously 'THAT'
    'n':'E', # 'THn' in the prelast sentence is obviously 'THE'
    'u':'D', # 'HAu' in the second dsentence maps to 'HAD'
    'o':'N', # 'AoD' in the first sentence could be 'AND' only
    't':'F', # 'tEET', second sentence -> 'FEET' or 'MEET'
    'w':'V', # 'EwEN', second sentence -> 'EVEN' only
    'e':'K', # 'eID', third row is 'KID'
    'f':'S', # 'FLAfK' could be "FLASK" only
    'r':'M', # 'rIDDLE' could be 'MIDDLE' only
    'z':'O', # 'IN THE MIDDLE zF THE' is obvious
    'x':'W', # 'xAS' is 'WAS'
    'y':'R', # 'SHOyTS' is 'SHORTS'
    'i':'G', # 'WEARINi' -> 'WEARING'
    'k':'Y', # 'I WAS WEARING ONLk SHORTS' is straightforward
    'h':'P', #  \/ descr is on the next line \/
    'q':'C', # 'hOqKET' may be 'POCKET'
    'l':'U', # 'IN ONE POCKET I PlT' -> 'PUT'
    'g':'B', # 'gUT I KNEW' -> 'BUT'
    'p':'Q', # 'A PACK WAS OUT OF THE pUESTION' -> 'QUESTION'
    'm':'X', # 'ANY EmTRA WEIGHT ON MY BODY' -> 'EXTRA'
    
    # Now missing J and Z
    'b':'Z', # have no idea what zbars are, but its better than jbars
    
    # The last pair that left
    'a':'J'
}
sub(encoded, mapTo)

# Making sure that I mapped all the letters
print(sorted(list(mapTo.keys())))
print(sorted(list(mapTo.values())))

# Copy from password_cracker.py
def getDictionary(filename):
    return [line[:-1] for line in open(filename, "r")]

# Inverting and lowercasing dictionary
inverted_dict = dict([[v.lower(),k] for k,v in mapTo.items()])


#
# Accepts map of users and their hashed passwords along with dictionary filename
# Tries all possible combinations of all transformations but salt firstly
# Then looks for a salted password
#
import hashlib
import progressbar
def password_cracker(toFind, filename):
    for pwd in progressbar.progressbar(getDictionary(filename), prefix='Trying all passwords: '):
        finalPwd = sub(pwd, inverted_dict)
        f = hashlib.md5
        if f(finalPwd.encode('utf-8')).hexdigest() == toFind:
            print("Found password for %s : %s" % (toFind, finalPwd))
        
filename = "files/dictionary.txt"
password_cracker("dfa1339508e1b702a4588a3209a8e0ec", filename);
