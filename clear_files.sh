# chmod +x clear_files.sh
# ./clear_files.sh

rm -r Admin/homomorphic_keys
rm -r Admin/root_CA
rm -r Client1/Files
rm -r Client2/Files
rm -r Server/Files
rm -r Server/Encrypted_Database
rm Client1/session.key
rm Client2/session.key
rm Server/session.key
rm Admin/admin
rm Client1/client
rm Client2/client
rm Server/server

mkdir Client1/Files
mkdir Client2/Files
mkdir Server/Files
