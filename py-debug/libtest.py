import os
import sys


dll_path = os.path.abspath("./lib")
if os.path.exists(dll_path):
    os.add_dll_directory(dll_path)
    print(f"Путь к DLL добавлен: {dll_path}")


from cheburnet import *

list = interception("www.youtube.com", 10)

print(list.decode('utf-8', errors='replace'))



# Code by 0b101100110010011100110001001010