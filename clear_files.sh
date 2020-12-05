# chmod +x clear_files.sh
# ./clear_files.sh

rm -r Admin/homomorphic_keys
rm -r Admin/root_CA
rm -r Client1/Files
rm -r Client2/Files
rm -r Server/Files
rm Client1/session.key
rm Client2/session.key
rm Server/session.key
rm Admin/admin
rm Client1/client1
rm Client2/client2
rm Server/server

mkdir Client1/Files
mkdir Client2/Files
mkdir Server/Files
