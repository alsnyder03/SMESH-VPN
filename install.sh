#!/bin/bash

pip install --upgrade -r requirements.txt

git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python || exit
pip install .

# Check if the installation was successful
if python3 -c "import oqs" &> /dev/null; then
    echo "liboqs-python installed successfully."
else
    echo "liboqs-python installation failed."
fi

# Clean up
cd ..
rm -rf liboqs-python