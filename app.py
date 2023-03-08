from flask import Flask, render_template, request

app = Flask("__name__")

@app.route("/")
def index():
    return render_template("index.html")

# ************************ CeasarEn ************************
@app.route("/ceasarEn", methods=['GET', 'POST'])
def CeasarEn():
    if request.method == "GET":
        # seems like no need
        # plaintext1 = request.form.get("plaintext1")
        # shiftvalue = request.form.get("shiftvalue")
        return render_template("ceasarEn.html")

    if request.method == 'POST':
        plaintext1 = str(request.form.get("plaintext1"))
        shiftvalue = request.form.get("shiftvalue")
        ciphertext1 = ""
        shiftvalue = int(shiftvalue)
        for i in range(len(plaintext1)):
            char = plaintext1[i]
 
            if (char == ' '):
                ciphertext1 += ' '
                continue

            # Encrypt uppercase characters
            if (char.isupper()):
                ciphertext1 += chr((ord(char) + shiftvalue - 65) % 26 + 65)
 
            # Encrypt lowercase characters
            else:
                ciphertext1 += chr((ord(char) + shiftvalue - 97) % 26 + 97)
        
        return render_template("ceasarEn.html", plaintext1=plaintext1, ciphertext1=ciphertext1,
        shiftvalue=shiftvalue)

# ************************ CeasarDe ************************

@app.route("/ceasarDe", methods=['GET', 'POST'])
def CeasarDe():
    if request.method == "GET":
        # seems like no need
        # plaintext1 = request.form.get("plaintext1")
        # shiftvalue = request.form.get("shiftvalue")
        return render_template("ceasarDe.html")

    if request.method == 'POST':
        # Decryption
        plaintext2 = ""
        ciphertext2 = str(request.form.get("ciphertext2"))
        shiftvalue = int(request.form.get("shiftvalue"))
        for i in range(len(ciphertext2)):
            char = ciphertext2[i]
            if (char == ' '):
                plaintext2 += ' '
                continue

            # Encrypt uppercase characters
            if (char.isupper()):
                plaintext2 += chr((ord(char) - shiftvalue - 65) % 26 + 65)
 
            # Encrypt lowercase characters
            else:
                plaintext2 += chr((ord(char) - shiftvalue - 97) % 26 + 97)

    
        return render_template("ceasarDe.html", plaintext2=plaintext2, ciphertext2=ciphertext2,
        shiftvalue=shiftvalue)
        

# ************************ rot13En ************************
@app.route("/rot13En", methods=['GET', 'POST'])
def Rot13En():
    if request.method == "GET":
        return render_template("rot13En.html")

    if request.method == 'POST':
        plaintext1 = str(request.form.get("plaintext1"))
        ciphertext1 = ""
        shiftvalue = 13
        for i in range(len(plaintext1)):
            char = plaintext1[i]
 
            if (char == ' '):
                ciphertext1 += ' '
                continue

            # Encrypt uppercase characters
            if (char.isupper()):
                ciphertext1 += chr((ord(char) + shiftvalue - 65) % 26 + 65)
 
            # Encrypt lowercase characters
            else:
                ciphertext1 += chr((ord(char) + shiftvalue - 97) % 26 + 97)

        return render_template("rot13En.html", plaintext1=plaintext1, ciphertext1=ciphertext1)

# ************************ rot13De ************************
@app.route("/rot13De", methods=['GET', 'POST'])
def Rot13De():
    if request.method == "GET":
        return render_template("rot13De.html")

    if request.method == 'POST':
        # Decryption
        shiftvalue = 13
        plaintext2 = ""
        ciphertext2 = str(request.form.get("ciphertext2"))
        for i in range(len(ciphertext2)):
            char = ciphertext2[i]
            if (char == ' '):
                plaintext2 += ' '
                continue

            # Encrypt uppercase characters
            if (char.isupper()):
                plaintext2 += chr((ord(char) - shiftvalue - 65) % 26 + 65)
 
            # Encrypt lowercase characters
            else:
                plaintext2 += chr((ord(char) - shiftvalue - 97) % 26 + 97)

        return render_template("rot13De.html", plaintext2=plaintext2, ciphertext2=ciphertext2)

# ************************ base64En ************************
import base64
def base64Encrypt(sample_string):
    sample_string_bytes = sample_string.encode("ascii", errors='ignore')
    base64_bytes = base64.b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode("ascii", errors='ignore')
    return base64_string

@app.route("/base64En", methods=['GET', 'POST'])
def Base64En():
    if request.method == "GET":
        return render_template("base64En.html")
    if request.method == "POST":
        plaintext1 = str(request.form.get('plaintext1'))
        ciphertext1 = ""
        ciphertext1 = base64Encrypt(plaintext1)

        return render_template("base64En.html", plaintext1=plaintext1, ciphertext1=ciphertext1)

# ************************ base64De ************************
import base64

def base64Decrypt(base64_string):
    base64_bytes = base64_string.encode("ascii", errors='ignore')
    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("ascii", errors='ignore')
    return sample_string

@app.route("/base64De", methods=['GET', 'POST'])
def Base64De():
    if request.method == "GET":
        return render_template("base64De.html")
    if request.method == "POST":
        # Decryption Base64
        ciphertext2 = str(request.form.get('ciphertext2'))
        plaintext2 = ""
        plaintext2 = base64Decrypt(ciphertext2)
        return render_template("base64De.html", plaintext2=plaintext2, ciphertext2=ciphertext2)

# ************************ reverseEn ************************
def reverseEncrypt(message, dict):
    rev_message = message[::-1]
    for i in dict:
        rev_message = rev_message.replace(i, dict[i])
    return rev_message + "aca"

@app.route("/reverseEn", methods=['GET', 'POST'])
def ReverseEn():
    if request.method == "GET":
        return render_template("reverseEn.html")
    if request.method == "POST":
        plaintext1 = str(request.form.get('plaintext1'))
        ciphertext1 = ""
        encDict = {"a" : "0", "e" : "1",
        "i" : "2", "o" : "3", 
        "u" : "4"} 
        ciphertext1 = reverseEncrypt(plaintext1, encDict)
        return render_template("reverseEn.html", plaintext1=plaintext1, ciphertext1=ciphertext1)

# ************************ reverseDe ************************
def reverseDecrypt(encMessage, dict):
    rev_message = encMessage[::-1]
    rev_message = rev_message[3:]
    for i in dict:
        rev_message = rev_message.replace(i, dict[i])
    return rev_message

@app.route("/reverseDe", methods=['GET', 'POST'])
def ReverseDe():
    if request.method == "GET":
        return render_template("reverseDe.html")
    if request.method == "POST":
        # Decryption ReverseAlgo
        decDict = {"0" : "a", "1" : "e",
        "2" : "i", "3" : "o", 
        "4" : "u"}
        ciphertext2 = str(request.form.get('ciphertext2'))
        plaintext2 = ""
        plaintext2 = reverseDecrypt(ciphertext2, decDict)
        return render_template("reverseDe.html", plaintext2=plaintext2, ciphertext2=ciphertext2)

# ************************ oneTimePadEn ************************
def cipherText(plain, k):
    if(len(plain) != len(k)):
        k1 = k
        j = 0
        while(len(plain) != len(k1)):
            if(j == (len(k))):
                j = 0
                continue
            k1 += k[j]
            j += 1
        # k1 is same length key
    else:
        k1 = k
    cipher = ""
    for i in range(len(plain)):
        t = ord(plain[i]) - 97 + ord(k1[i]) - 97
        if (t >= 26):
            t -= 26
        cipher += chr(t + 97)
    return cipher

@app.route("/oneTimePadEn", methods=['GET', 'POST'])
def OneTimePadEn():
    if request.method == "GET":
        return render_template("oneTimePadEn.html")

    if request.method == 'POST':
        plaintext1 = str(request.form.get("plaintext1"))
        key = str(request.form.get("key"))
        ciphertext1 = ""
        # logic for encryption starts
        ciphertext1 = cipherText(plaintext1, key)

        return render_template("oneTimePadEn.html", plaintext1=plaintext1, ciphertext1=ciphertext1,
        key=key)

# ************************ oneTimePadDe ************************
def originalText(cipher, k):
    if(len(cipher) != len(k)):
        k1 = k
        j = 0
        while(len(cipher) != len(k1)):
            if(j == (len(k))):
                j = 0
                continue
            k1 += k[j]
            j += 1
        # k1 is same length key
    else:
        k1 = k
    plain = ""
    for i in range(len(cipher)):
        t = (ord(cipher[i]) - 97) - (ord(k1[i]) - 97)
        if (t < 0):
            t += 26
        plain += chr(t + 97)
    return plain

@app.route("/oneTimePadDe", methods=['GET', 'POST'])
def OneTimePadDe():
    if request.method == "GET":
        return render_template("oneTimePadDe.html")

    if request.method == 'POST':
        # Decryption
        plaintext2 = ""
        ciphertext2 = str(request.form.get("ciphertext2"))
        key = str(request.form.get("key"))
        plaintext2 = originalText(ciphertext2, key)

        return render_template("oneTimePadDe.html", plaintext2=plaintext2, ciphertext2=ciphertext2,
        key=key)

# ************************ sha512En ************************
import hashlib

def getCipher(plaintext1):
    res = hashlib.sha512(plaintext1.encode())
    return res.hexdigest()

@app.route("/sha512En", methods=['GET', 'POST'])

def Sha512En():
    if request.method == "GET":
        return render_template("sha512En.html")

    if request.method == 'POST':
        plaintext1 = str(request.form.get("plaintext1"))
        ciphertext1 = getCipher(plaintext1)

    return render_template("sha512En.html", plaintext1=plaintext1, ciphertext1=ciphertext1) 

# ************************ sha512De ************************
def areSame(hash1, hash2):
    if (hash1 == hash2):
        return "Entered Hashes Were A Match!!!\nThe Hashes Were Generated From The Same Password."
    else:
        return "Entered Hashes Were Not A Match!!!\nThe Hashes Were Not Generated From The Same Password."

@app.route("/sha512De", methods=['GET', 'POST'])

def Sha512De():
    if request.method == "GET":
        return render_template("sha512De.html")

    if request.method == 'POST':
        hash1 = str(request.form.get("hash1"))
        hash2 = str(request.form.get("hash2"))
        verdict = areSame(hash1, hash2)
        
    return render_template("sha512De.html", verdict=verdict)

if __name__ == "__main__":
    app.run(debug=True)