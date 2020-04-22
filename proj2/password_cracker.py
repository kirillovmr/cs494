import progressbar
import hashlib
import json

# Yes, supplementary functions are just single line and not documented
# BUT thats because list comprehensions in python processes an array in the speed of C language
# Therefore optimization and time is preferred in this case

# Returns list with all the words from the dictionary
def getDictionary(filename):
    return [line[:-1] for line in open(filename, "r")]


# Returns text with salt added
def salt(text):
    return [text + str(i).zfill(5) for i in range(100000)]


# Returns text under caesar cipher
# Works for lowercase only (no need capital one for this assignment)
def caesar(text):
    return ["".join(chr((ord(char) - 97 + shift) % 26 + 97) if char.isalpha() else char for char in text) for shift in range(26)]


# Returns text in its basic leet representation
def leet(text):
    chars = {"a":"4","e":"3","g":"6","i":"1","o":"0","s":"5","t":"7","z":"2"}
    return "".join(chars[char.lower()] if char in chars else char for char in text)


#
# Accepts map of users and their hashed passwords along with dictionary filename
# Tries all possible combinations of all transformations but salt firstly
# Then looks for a salted password
#
def password_cracker(toFind, filename):
    # Map of hash size to its corresponding function
    hashMap = {32:hashlib.md5, 40:hashlib.sha1, 64:hashlib.sha256, 128:hashlib.sha512}
    found = {}
    error = {}
    
    # Handles the case if hashed password has len which is not defined in hashMap above
    for user in list(toFind):
        if not hashMap.get(len(toFind[user])):
            print("! Have no function defined for hash %s" % toFind[user])
            error[user] = toFind[user]
            del toFind[user]

    # Lets try all but salt
    for pwd in progressbar.progressbar(getDictionary(filename), prefix='All but salt: '):
        for pwdLeet in [pwd, leet(pwd)]:
            for pwdCaesar in caesar(pwdLeet):
                for user in list(toFind):
                    f = hashMap.get(len(toFind[user]))
                    finalPwd = pwdCaesar
                    if f(finalPwd.encode('utf-8')).hexdigest() == toFind[user]:
                        print("Found password for %s : %s" % (user, finalPwd))
                        found[user] = {
                            "password":finalPwd,
                            "hashFunc":f.__name__,
                            "seq":"%s -leet> %s -caesar> %s" % (pwd, pwdLeet, pwdCaesar)
                        }
                        del toFind[user]
                        
    # Salted password
    for pwd in progressbar.progressbar(getDictionary(filename), prefix='Salt: '):
        for pwdSalted in salt(pwd):
            for user in list(toFind):
                f = hashMap.get(len(toFind[user]))
                if f(pwdSalted.encode('utf-8')).hexdigest() == toFind[user]:
                    print("Found password for %s : %s" % (user, pwdSalted))
                    found[user] = {
                        "password":pwdSalted,
                        "hashFunc":f.__name__,
                        "seq":"%s -salt> %s" % (pwd, pwdSalted)
                    }
                    del toFind[user]
                
    # Print results
    print("\n----------------")
    print("Found passwords:")
    print(json.dumps(found, indent=2))
    
    print("\nErrors in hash length:")
    print(json.dumps(error, indent=2))
    
    print("\nNot found:")
    print(json.dumps(toFind, indent=2))
        

# How I was using it:
filename = "files/dictionary.txt"
toFind = {
    "user1":"2224e8c5299874a5fe44a8de2f31c94e",
    "user2":"e90829e04a20e9b49a4178f65b9a1a725191bd99fbd8071fa9cb6ee2552f2bc5",
    "user3":"6de664f06c446616eb374e1ba109a24b9172929162937831b18d7812fc76e1a3a8c9f4d1443d300b1b6a0419e80572ab0d5788f5faf28c869e06c84fe0242d96",
    "user4":"21d5c27a7e06317d1d02e0135a76454971e2c6d2",
    "user5":"aec0e78824de1205cf98384780983c6f2b7c03f8a6e5036a508ece76f1b3c5a7",
    "user6":"fa5da9b79da364f5aea54b2b9cdedaa4fff6f522be7f1e2b5f13f399bd1c94ca059220d7fd1fed2a31a60068c2d13007da7bf987b1623a7fc0ada0390fafb584",
    "user7":"dfa1339508e1b702a4588a3209a8e0ec"
}
password_cracker(toFind, filename);
