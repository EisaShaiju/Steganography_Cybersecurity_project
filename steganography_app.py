import streamlit as st
import numpy as np
import cv2
from PIL import Image
import io
from aes_encryption import encrypt_message, decrypt_message  # Import AES functions


# Function to encode text into an image
def encode_image(image, secret_msg, passkey):
    encrypted_msg = encrypt_message(secret_msg, passkey)  # Encrypt message
    bin_secret_msg = ''.join(format(ord(i), '08b') for i in encrypted_msg)
    data_len = len(bin_secret_msg)
    img_array = np.array(image)
    height, width, _ = img_array.shape
    total_pixels = height * width

    if data_len > total_pixels:
        st.error("Message is too long for this image.")
        return None

    idx = 0
    for i in range(height):
        for j in range(width):
            if idx < data_len:
                img_array[i, j, 0] = (img_array[i, j, 0] & 0xFE) | int(bin_secret_msg[idx])
                idx += 1
            else:
                break

    return Image.fromarray(img_array)


# Function to decode text from an image
def decode_image(image, passkey):
    img_array = np.array(image)
    bin_secret_msg = ""
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            bin_secret_msg += str(img_array[i, j, 0] & 1)

    bytes_list = [bin_secret_msg[i: i + 8] for i in range(0, len(bin_secret_msg), 8)]
    extracted_msg = "".join([chr(int(b, 2)) for b in bytes_list])

    decrypted_msg = decrypt_message(extracted_msg, passkey)  # Decrypt message
    return decrypted_msg


# Streamlit UI
st.title("🔒 Steganography with AES Encryption")

option = st.selectbox("Choose an option:", ["Encode Message", "Decode Message"])

if option == "Encode Message":
    uploaded_image = st.file_uploader("Upload an image", type=["png", "jpg", "jpeg"])
    secret_msg = st.text_area("Enter secret message")
    passkey = st.text_input("Enter passkey", type="password")

    if uploaded_image and secret_msg and passkey:
        image = Image.open(uploaded_image)
        encoded_img = encode_image(image, secret_msg, passkey)

        if encoded_img:
            buf = io.BytesIO()
            encoded_img.save(buf, format="PNG")
            st.download_button("Download Encoded Image", data=buf.getvalue(), file_name="encoded_image.png",
                               mime="image/png")

elif option == "Decode Message":
    uploaded_image = st.file_uploader("Upload an encoded image", type=["png"])
    passkey = st.text_input("Enter passkey", type="password")

    if uploaded_image and passkey:
        image = Image.open(uploaded_image)
        decoded_msg = decode_image(image, passkey)
        st.write("Decoded Message:", decoded_msg)
