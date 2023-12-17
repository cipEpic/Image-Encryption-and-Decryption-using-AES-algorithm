# from __future__ import division, print_function, unicode_literals

# import sys
# import random
# import argparse
# import logging
# from tkinter import *
# from tkinter import filedialog
# from tkinter import messagebox
# import os
# from PIL import ImageTk , Image
# from PIL import Image
# import math
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# from Crypto.Random import get_random_bytes
# import hashlib
# import binascii
# import numpy as np

from __future__ import division, print_function, unicode_literals

import sys
import random
import argparse
import logging
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
import os
from PIL import ImageTk , Image
from PIL import Image
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import binascii
import numpy as np


global password 
global counter1

# Function to get the counter value
def get_counter():
    try:
        with open('counter.txt', 'r') as file:
            return int(file.read())
    except FileNotFoundError:
        return 1
    

# Function to save the counter value
def save_counter(counter):
    with open('counter.txt', 'w') as file:
        file.write(str(counter))

# Function to increment counter value
def increment_counter():
    counter = get_counter()
    counter += 1
    save_counter(counter)


# Fungsi untuk memuat gambar
def load_image(name):
    return Image.open(name)

# Fungsi untuk menyiapkan gambar pesan
def prepare_message_image(image, size):
    if size != image.size:
        image = image.resize(size, Image.ANTIALIAS)
    return image

# Fungsi untuk menghasilkan gambar rahasia
def generate_secret(size, secret_image=None):
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))

    for x in range(0, 2 * width, 2):
        for y in range(0, 2 * height, 2):
            color1 = np.random.randint(255)
            color2 = np.random.randint(255)
            color3 = np.random.randint(255)
            new_secret_image.putpixel((x, y), (color1, color2, color3))
            new_secret_image.putpixel((x + 1, y), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x, y + 1), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x + 1, y + 1), (color1, color2, color3))

    return new_secret_image

# Fungsi untuk menghasilkan gambar terenkripsi
def generate_ciphered_image(secret_image, prepared_image):
    width, height = prepared_image.size
    ciphered_image = Image.new(mode="RGB", size=(width * 2, height * 2))
    
    for x in range(0, width * 2, 2):
        for y in range(0, height * 2, 2):
            sec = secret_image.getpixel((x, y))
            msssg = prepared_image.getpixel((int(x / 2), int(y / 2)))
            color1 = (msssg[0] + sec[0]) % 256
            color2 = (msssg[1] + sec[1]) % 256
            color3 = (msssg[2] + sec[2]) % 256
            ciphered_image.putpixel((x, y), (color1, color2, color3))
            ciphered_image.putpixel((x + 1, y), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x, y + 1), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x + 1, y + 1), (color1, color2, color3))

    return ciphered_image

# Fungsi untuk menghasilkan gambar asli dari gambar terenkripsi
def generate_image_back(secret_image, ciphered_image):
    width, height = secret_image.size
    new_image = Image.new(mode="RGB", size=(int(width / 2), int(height / 2)))

    for x in range(0, width, 2):
        for y in range(0, height, 2):
            sec = secret_image.getpixel((x, y))
            cip = ciphered_image.getpixel((x, y))
            color1 = (cip[0] - sec[0]) % 256
            color2 = (cip[1] - sec[1]) % 256
            color3 = (cip[2] - sec[2]) % 256
            new_image.putpixel((int(x / 2), int(y / 2)), (color1, color2, color3))

    return new_image

# ... (Previous code remains unchanged) ...

def level_one_encrypt(Imagename, password, output_folder, counter):

    message_image = load_image(Imagename)
    size = message_image.size
    width, height = size

    secret_image = generate_secret(size)
    prepared_image = prepare_message_image(message_image, size)
    ciphered_image = generate_ciphered_image(secret_image, prepared_image)

    # Create a folder with the provided counter value
    combined_folder = os.path.join(output_folder, f"Images{counter}")
    os.makedirs(combined_folder, exist_ok=True)

    # Save both images inside the combined_folder
    secret_image_name = os.path.join(combined_folder, f"secret_{width}x{height}_encrypt.jpeg")
    secret_image.save(secret_image_name)
    ciphered_image_name = os.path.join(combined_folder, f"ciphered_{width}x{height}_encrypt.jpeg")
    ciphered_image.save(ciphered_image_name)

    return ciphered_image_name


# Fungsi untuk membangun gambar terenkripsi
def construct_enc_image(ciphertext, relength, width, height, output_folder):
    global counter 
    counter = get_counter()
     # Create a folder with the counter value
    enc_folder = os.path.join(output_folder, f"Images{counter}")
    os.makedirs(enc_folder, exist_ok=True)
    # Convert ciphertext to hexadecimal representation
    asciicipher = binascii.hexlify(ciphertext)

    # Dictionary to replace characters with numbers
    reps = {
        'a': '1', 'b': '2', 'c': '3', 'd': '4', 'e': '5', 'f': '6', 'g': '7', 'h': '8', 'i': '9',
        'j': '10', 'k': '11', 'l': '12', 'm': '13', 'n': '14', 'o': '15', 'p': '16', 'q': '17',
        'r': '18', 's': '19', 't': '20', 'u': '21', 'v': '22', 'w': '23', 'x': '24', 'y': '25', 'z': '26'
    }

    def replace_all(texts, dict):
        for i, j in dict.items():
            texts = texts.replace(i.encode("utf-8"), j.encode("utf-8"))
        return texts.decode("utf-8")

    # Replace ASCII characters in ciphertext with corresponding numbers
    asciiciphertxt = replace_all(asciicipher, reps)

    # Constructing the encrypted image
    step = 3
    encimageone = [asciiciphertxt[i:i + step] for i in range(0, len(asciiciphertxt), step)]

    if int(encimageone[len(encimageone) - 1], 16) < 100:
        encimageone[len(encimageone) - 1] += "1"

    if len(encimageone) % 3 != 0:
        while (len(encimageone) % 3 != 0):
            encimageone.append("101")

    # Convert alphanumeric characters to integers and form tuples of RGB values
    encimagetwo = [
        (int(''.join(filter(str.isalnum, encimageone[i])), 16), int(''.join(filter(str.isalnum, encimageone[i + 1])), 16),
         int(''.join(filter(str.isalnum, encimageone[i + 2])), 16))
        for i in range(0, len(encimageone), step)
    ]

    while (int(relength) != len(encimagetwo)):
        encimagetwo.pop()

    # Create a new image and store the RGB tuples as pixel data
    encim = Image.new("RGB", (int(width), int(height)))
    encim.putdata(encimagetwo)
    
    # Save the image in the enc_folder
    encim_name = os.path.join(enc_folder, f"visual_encrypt_{counter}.jpeg")
    encim.save(encim_name)

    # Increment counter for the next iteration

    return encim_name


# Initialize a list to hold encrypted image details
encrypted_images = []

def encrypt(imagename, password, output_folder):
    global counter
    counter = get_counter() 
    increment_counter() # Reset counter for each encryption process

    plaintext = list()
    plaintextstr = ""

    im = Image.open(imagename)
    pix = im.load()

    width = im.size[0]
    height = im.size[1]

    # Break up the image into a list, each with pixel values and then append to a string
    for y in range(0, height):
        for x in range(0, width):
            plaintext.append(pix[x, y])

    # Add 100 to each tuple value to make sure each is 3 digits long
    for i in range(0, len(plaintext)):
        for j in range(0, 3):
            aa = int(plaintext[i][j]) + 100
            plaintextstr = plaintextstr + str(aa)

    # Length save for encrypted image reconstruction
    relength = len(plaintext)

    # Append dimensions of image for reconstruction after decryption
    plaintextstr += "h" + str(height) + "h" + "w" + str(width) + "w"

    # Ensure that plaintextstr length is a multiple of 16 for AES. If not, append "n"
    while len(plaintextstr) % 16 != 0:
        plaintextstr = plaintextstr + "n"

    # Encrypt plaintext
    obj = AES.new(password, AES.MODE_CBC)
    plaintextcode = plaintextstr.encode("utf-8")
    ciphertext = obj.encrypt(pad(plaintextcode, AES.block_size))

    # Call construct_enc_image function first
    encim_name = construct_enc_image(ciphertext, relength, width, height, output_folder)
    print("1-Share Encryption done.......")

    # Create a folder with the provided counter value
    combined_folder = os.path.join(output_folder, f"Images{counter}")
    os.makedirs(combined_folder, exist_ok=True)

    # Write ciphertext to file for analysis
    cipher_name = "Images{counter}" + ".crypt"
    cipher_path = os.path.join(combined_folder, f"Images{counter}.crypt")
    try:
        with open(cipher_path, 'wb') as g:
            g.write(ciphertext)
        print(f"Ciphertext saved to {cipher_path}")
    except FileNotFoundError as fnfe:
        print(f"Error: Output folder not found - {fnfe}")
    except PermissionError as pe:
        print(f"Error: Permission denied - {pe}")
    except Exception as e:
        print(f"Error while saving the ciphertext: {e}")

    # Call level_one_encrypt function
    ciphered_image_name = level_one_encrypt(imagename, password, output_folder, counter)  # Call level_one_encrypt without capturing its output

    combined_folder1 = os.path.join(output_folder, f"Images{counter}")

    # Full path to the .crypt file
    crypt_file_path = os.path.join(combined_folder1, f"Images{counter}.crypt")

    # Store encrypted image details in the list
    encrypted_image_info = {
        "filename": crypt_file_path,
        "width": width,
        "height": height,
        "output_folder": combined_folder1
    }
    encrypted_images.append(encrypted_image_info)
    print("Encrypted Images List:", encrypted_images)

    return encim_name

def decrypt(cipher_name, password, width, height, output_folder):
    global counter1

    with open('counter.txt', 'r') as file:
        counter1 = int(file.read())
        
        # Check if the folder exists
        if os.path.exists(output_folder):
            # Retrieve decryption information based on the filename
            secret_image_path = os.path.join(output_folder, f"secret_{width}x{height}_encrypt.jpeg")
            encrypted_image_path = os.path.join(output_folder, f"ciphered_{width}x{height}_encrypt.jpeg")

            # Check if the encrypted image exists in the folder
            if os.path.exists(secret_image_path) and os.path.exists(encrypted_image_path):
                secret_image_path = os.path.join(output_folder, f"secret_{width}x{height}_encrypt.jpeg")
                encrypted_image_path = os.path.join(output_folder, f"ciphered_{width}x{height}_encrypt.jpeg")

            # Check if the encrypted image exists in the folder
            if os.path.exists(secret_image_path) and os.path.exists(encrypted_image_path):
                secret_image = Image.open(secret_image_path)
                encrypted_image = Image.open(encrypted_image_path)

                # Perform decryption and save the image
                new_image = generate_image_back(secret_image, encrypted_image)
                combined_path = os.path.join(output_folder, output_folder)
                os.makedirs(combined_path, exist_ok=True)
                cipher_path1 = os.path.join(combined_path, f"2-share_decrypt.jpeg")
                new_image.save(cipher_path1)

                # Read ciphertext from the specified file
                with open(cipher_name, 'rb') as cipher_file:
                    ciphertext = cipher_file.read()

                # Perform decryption
                obj2 = AES.new(password, AES.MODE_CBC)
                decrypted = obj2.decrypt(ciphertext)

                # Remove padding after decryption (if padding was added during encryption)
                decrypted = unpad(decrypted, AES.block_size)

                a1="n"
                a11 = a1.encode("utf-8")
                a2="w"
                a21 = a2.encode("utf-8")
                a3="h"
                a31 = a3.encode("utf-8")
            # a4=bytes("w")
                a5=b""
                a51 = a5

                decrypted = decrypted.replace(a11,a51)

                # extract dimensions of images
                newwidth = decrypted.split(a21)[1]
                newheight = decrypted.split(a31)[1]

                # replace height and width with empty space in decrypted plaintext
                heightr = b"h" + newheight + b"h"
                widthr = b"w" + newwidth + b"w"
                decrypted = decrypted.replace(heightr, a51)
                decrypted = decrypted.replace(widthr, a51)

                # reconstruct the list of RGB tuples from the decrypted plaintext
                step = 3
                finaltextone = [decrypted[i:i + step] for i in range(0, len(decrypted), step)]
                finaltexttwo = []
                
                # convert the RGB tuples to integers (handling invalid literals)
                for i in range(0, len(finaltextone), step):
                    try:
                        r = int(finaltextone[i]) - 100
                        g = int(finaltextone[i + 1]) - 100
                        b = int(finaltextone[i + 2]) - 100
                        finaltexttwo.append((r, g, b))
                    except ValueError:
                        pass

                # reconstruct image from the list of pixel RGB tuples
                newim = Image.new("RGB", (int(newwidth), int(newheight)))
                newim.putdata(finaltexttwo)
                cipher_path2 = os.path.join(combined_path, f"visual_decrypt.jpeg")
                newim.save(cipher_path2)
                print("Visual Decryption done......")
               

def pass_alert():
   messagebox.showinfo("Password Alert","Please enter a password.")

def enc_success(imagename):
   messagebox.showinfo("Success","Encrypted Image: " + imagename)

# image encrypt button event
def image_open():
    global file_path_e

    enc_pass = passg.get()
    if enc_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(enc_pass.encode("utf-8")).digest()
        filename = filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)
        
        # Mendapatkan direktori dari file gambar yang dienkripsi
        output_folder = os.path.dirname(filename)
        
        # Memanggil fungsi encrypt() dengan tiga argumen yang diperlukan
        encrypt(filename, password, output_folder)

# image decrypt button event
def cipher_open():
    global file_path_d

    dec_pass = passg.get()
    if dec_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(dec_pass.encode("utf-8")).digest()
        # filename = filedialog.askopenfilename()
        # file_path_d = os.path.dirname(filename)
        # print(file_path_d)
        
        # # Retrieve decryption information based on filename
        # decrypted_image_info = None
        # print("Encrypted Images List:", encrypted_images)
        # for image_info in encrypted_images:
        #     normalized_path = os.path.normpath(image_info["filename"])
        #     normalized_filename = os.path.normpath(filename)
        #     print(normalized_path)
        #     print(normalized_filename)
        #     if normalized_path == normalized_filename:
        #         decrypted_image_info = image_info
        #         break

        # print(decrypted_image_info)
        filename = filedialog.askopenfilename()
        print(filename)

        # Retrieve decryption information based on filename
        decrypted_image_info = None
        print("Encrypted Images List:", encrypted_images)
        for image_info in encrypted_images:
            normalized_path = os.path.normpath(image_info["filename"])
            normalized_filename = os.path.normpath(filename)
            print(normalized_path)
            print(normalized_filename)
            if normalized_path == normalized_filename:
                decrypted_image_info = image_info
                break

        print(decrypted_image_info)


        if decrypted_image_info:
            width = decrypted_image_info["width"]
            height = decrypted_image_info["height"]
            output_folder = decrypted_image_info["output_folder"]

            decrypt(filename, password, width, height, output_folder)
        else:
            # Handle case when decryption information is not found for the selected file
            messagebox.showinfo("Decryption Error", "Decryption information not found for the selected file.")


class App:
  def __init__(self, master):
    global passg
    title = "Image Encryption"
    author = "Made by Kelompok 1"
    msgtitle = Message(master, text =title)
    msgtitle.config(font=('helvetica', 17, 'bold'), width=200)
    msgauthor = Message(master, text=author)
    msgauthor.config(font=('helvetica',10), width=200)

    canvas_width = 200
    canvas_height = 50
    w = Canvas(master,
           width=canvas_width,
           height=canvas_height)
    msgtitle.pack()
    msgauthor.pack()
    w.pack()

    passlabel = Label(master, text="Enter Encrypt/Decrypt Password:")
    passlabel.pack()
    passg = Entry(master, show="*", width=20)
    passg.pack()

    self.encrypt = Button(master,
                         text="Encrypt", fg="black",
                         command=image_open, width=25,height=5)
    self.encrypt.pack(side=LEFT)
    self.decrypt = Button(master,
                         text="Decrypt", fg="black",
                         command=cipher_open, width=25,height=5)
    self.decrypt.pack(side=RIGHT)




# ------------------ MAIN -------------#
root = tk.Tk()
root.wm_title("Image Encryption")
# Replace 'path/to/your/icon.ico' with the actual path to your icon file
root.iconbitmap('Images\Logo-unud-baru.ico')
app = App(root)
root.mainloop()