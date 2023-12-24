import os

project_name = "MultiCrypt"
version = "0.0.1"
author = "emendir"
description = "A single unified interface for working with alternative cryptographic algorithms."
long_description = ""
if os.path.exists("ReadMe.md"):
    with open("ReadMe.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()
long_description_content_type = "text/markdown"
url = "https://ipfs.io/ipns/k2k4r8nismm5mmgrox2fci816xvj4l4cudnuc55gkfoealjuiaexbsup/"

project_urls = {
    "Source Code on IPNS": "ipns://k2k4r8nismm5mmgrox2fci816xvj4l4cudnuc55gkfoealjuiaexbsup/",
    "Github": ""
}
classifiers = [
    "Programming Language :: Python :: 3",
    "Operating System :: OS Independent",
]

python_requires = ">=3.6"

# load install_requires data from requirements.txt
requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
install_requires = []
if os.path.exists(requirements_path):
    with open(requirements_path, 'r') as file:
        install_requires = [line.strip('\n') for line in file.readlines()]
