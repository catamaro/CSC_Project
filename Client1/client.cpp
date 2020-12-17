#include "../resources.h"

/******************************************** OpenSSL functions *********************************************/

// function to encode message with private and public key
void encode_message(string message, int val_flag)
{
    string message_encoded;

    // create file with message to be encrypted
    ofstream infile("Files/message.txt");

    infile << message << endl;

    infile.close();

    // create file with name of client to be encrypted
    ofstream infile2("Files/name.txt");

    infile2 << "Client1" << endl;

    infile2.close();

    // extract server's public key from certificate
    system("openssl x509 -pubkey -noout -in Files/Server-cert.crt > Files/Server-publ.pem\n");
    // generate random password file
    system("openssl rand -base64 32 > session.key\n");
    // session key encrypted with server's public key
    system("openssl rsautl -encrypt -pubin -inkey Files/Server-publ.pem -in session.key -out Files/session.key.enc\n");
    // session key signed with client's private key
    system("openssl dgst -sha256 -sign Files/Client1-priv.pem -out Files/Client1-sign.sha256 Files/session.key.enc");
    // encrypt message with session key
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/message.txt -out Files/Client1-message.enc -pass file:./session.key\n");
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/name.txt -out Files/name.enc -pass file:./session.key\n");
    if(val_flag) system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/values.txt -out Files/Client1-values.enc -pass file:./session.key\n");

    // remove unnecessary files
    system("rm Files/message.txt\n");
    if(val_flag) system("rm Files/values.txt\n");

    // moves encoded session-key, encoded message and certificate to server's folder
    system("mv Files/Client1-message.enc ../Server/Messages\n");
    if(val_flag) system("mv Files/Client1-values.enc ../Server/Messages\n");
    system("mv Files/session.key.enc ../Server/Messages\n");
    system("mv Files/name.enc ../Server/Messages\n");
    system("mv Files/Client1-sign.sha256 ../Server/Messages\n");
    system("cp Files/Client1-cert.crt ../Server/Messages\n");
}
// function to verify files in client folder, certificates and keys
bool verify_documents()
{
    // check if root_ca is valid
    string root_id;

    ifstream root("Files/root_ca.crt");
    if (!root.fail())
    {
        system("openssl x509 -in Files/root_ca.crt -noout -pubkey > Files/root-publ.key\n");
        system("openssl x509 -noout -subject -in Files/root_ca.crt | sed -n 's/.*CN = \\([^,]*\\).*/\\1/p' > Files/root_id.txt\n");
        root_id = load_string("Files/root_id.txt");

        root.close();
        system("rm Files/root_id.txt\n");

        if (root_id.compare("root\n") != 0)
        {
            cout << "CA inválido: não corresponde à root\n";
            return false;
        }
    }
    else
    {
        cout << "Cannot locate root_ca certificate" << endl;
        return false;
    }

    // check if client certificate is valid
    system("openssl verify -CAfile Files/root_ca.crt Files/Client1-cert.crt > Files/verified.txt");

    // load verified.txt to confirm signature
    string sign_check = load_string("Files/verified.txt");
    system("rm Files/verified.txt\n");

    if (sign_check.find("Files/Client1-cert.crt: OK") != 0)
    {
        cout << "\nerror: Signature not valid! Message will not be considered" << endl;
        return false;
    }

    // check if client's private key in coherent with clients certificate
    int crt = system("openssl x509 -noout -modulus -in Files/Client1-cert.crt| openssl md5");
    int key = system("openssl rsa -noout -modulus -in Files/Client1-priv.pem | openssl md5");

    if (crt != key)
    {
        cout << "Client's private key doesn't match certificate" << endl;
        return false;
    }
    return true;
}
// function to decode message with private and public key
void decode_message(int query_num)
{
    string reply_decoded;

    // descrypt message with session key
    if(query_num == 4 || query_num == 5 || query_num == 6) system("openssl enc -d -aes-256-cbc -pbkdf2 -in Answers/query_result.enc -out Answers/query_result.txt -pass file:./session.key\n");
    if(query_num == 4 || query_num == 5 || query_num == 6) system("openssl enc -d -aes-256-cbc -pbkdf2 -in Answers/query_result_2.enc -out Answers/query_result_2.txt -pass file:./session.key\n");

    // remove unnecessary files: session key and encrypted query result
    system("rm session.key");
    if(query_num == 4 || query_num == 5 || query_num == 6) system("rm Answers/query_result.enc Answers/query_result_2.enc");
}

/******************************************** SEAL functions ************************************************/

// function to convert value from decimal to binary
vector<int> dec_to_binary(int number)
{
    vector<int> binary;
    int i;

    for (i = 0; i < 8; i++)
    {
        binary.push_back(number % 2);
        number = number / 2;
    }
    if (number > 0)
    {
        cout << "Erro: número com mais de 8 bits. Por favor insira um número mais pequeno \n";
        exit(1);
    }

    return binary;
}
// function to encrypt binaries of values
vector<Ciphertext> encrypt_binaries(vector<int> binary, Encryptor *encriptor)
{
    Plaintext binary_plain;
    int size = binary.size();
    vector<Ciphertext> encrypted(size);
    int i;
    for (i = 0; i < size; i++)
    {
        binary_plain = to_string(binary.at(i));
        (*encriptor).encrypt(binary_plain, encrypted.at(i));
    }

    return encrypted;
}

vector<int> decrypt_binaries(vector<Ciphertext> results)
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(64);
    SEALContext context(parms);

    SecretKey private_key;
    ifstream stream_private_Key;
    stream_private_Key.open("Files/DB_private.key", ios::binary);
    private_key.load(context, stream_private_Key);
    stream_private_Key.close();

    Decryptor decryptor(context, private_key);

    Plaintext plain_result;
    vector<string> comparasion(3);
    int i;
    vector<int> int_results(3);

    for (i = 0; i < 3; i++)
    {
        if (decryptor.invariant_noise_budget(results.at(i)) == 0)
        {
            /*if (i = 2) //B>A usualmente dá erro, mas pode ser obtido com uma conjunção de A=B e A>B
            {
                int_results.at(i) = !int_results.at(1) & !int_results.at(0);
            }
            else
            {*/
                cout << "Erro: Noise budget nulo\n";
            //}
        }
        else
        {
            decryptor.decrypt(results.at(i), plain_result);
            comparasion.at(i) = plain_result.to_string();
            int_results.at(i) = stoi(comparasion.at(i), nullptr, 10);
        }
    }

    cout << "A=B: " << int_results.at(0) << "\n";
    cout << "A>B: " << int_results.at(1) << "\n";
    cout << "A<B: " << int_results.at(2) << "\n";

    return int_results;
}
// function to encrypt values with Homomorphic Database Key
void encode_values(vector<string> values)
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(64);
    SEALContext context(parms);

    ifstream private_key_file;
    SecretKey private_key;

    private_key_file.open("Files/DB_private.key", ios::binary);
    private_key.load(context, private_key_file);

    Decryptor decryptor(context, private_key);

    ifstream public_key_file;
    PublicKey public_key;

    public_key_file.open("Files/DB_public.key", ios::binary);
    public_key.load(context, public_key_file);

    Evaluator evaluator(context);
    Encryptor encryptor(context, public_key);

    vector<int> binary;
    vector<Ciphertext> binary_encrypt;
    Ciphertext full_encrypt;
    Plaintext full_plain;

    ofstream values_file;
    values_file.open("Files/values.txt", ios::binary);

    for(int i=0; i<values.size(); i++){
        /*Encriptar nº completo*/
        full_plain = values.at(i);
        encryptor.encrypt(full_plain, full_encrypt);

        auto size_encrypted = full_encrypt.save(values_file);

        binary = dec_to_binary(stoi(values.at(i)));

        /*Encriptar bit a bit*/
        binary_encrypt = encrypt_binaries(binary, &encryptor);
        for(int i=0; i<binary.size(); i++) binary_encrypt.at(i).save(values_file);
    }

    values_file.close();
}
// function to decrypt values with Homomorphic Database Key
void decode_values(){
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(64);
    SEALContext context(parms);

    ifstream private_key_file;
    SecretKey private_key;

    private_key_file.open("Files/DB_private.key", ios::binary);
    private_key.load(context, private_key_file);

    Decryptor decryptor(context, private_key);

    Ciphertext full_encrypt;
    Plaintext plain_hex;
    int plain_dec;

    // file with number of values returned and column names
    ifstream query_result_2("Answers/query_result_2.txt");
    string col_name;

    getline(query_result_2, col_name);
    int num_values = stoi(col_name);

    //  files with encrypted values
    ifstream values_file;
    values_file.open("Answers/query_result.txt", ios::binary);
    string result_string("");

    cout << "number of values sent " << col_name << endl;

    for(int i=0; i<num_values; i++){
        full_encrypt.load(context, values_file);
        decryptor.decrypt(full_encrypt, plain_hex);
        
        plain_dec = hex_to_dec(plain_hex);
        getline(query_result_2, col_name);

        if (plain_dec != 0) cout << col_name << " " << to_string(plain_dec) << endl;
    }

    system("rm Answers/query_result.txt Answers/query_result_2.txt");
}

/***************************************** Client Aux Functions *********************************************/
// function to print possible query commands
void print_commands()
{
    cout << "+-------------------------------------------------------------------------------------------------------------------------------------+" << endl;
    cout << "| Commands                   | Syntax                                                                                                 |" << endl;
    cout << "+----------------------------+--------------------------------------------------------------------------------------------------------+" << endl;
    cout << "| 1. Create new table        | CREATE TABLE tablename (col1name, col2name, …, colNname)                                               |" << endl;
    cout << "| 2. Insert row in table     | INSERT INTO TABLE tablename (col1name, … , colNname) VALUES (value1, .., valueN)                       |" << endl;
    cout << "| 3. Delete row from table   | DELETE linenum FROM tablename                                                                          |" << endl;
    cout << "| 4. Select row from table   | SELECT ROW linenum FROM tablename                                                                      |" << endl;
    cout << "| 5. Query table             | SELECT col1name, .., colNname FROM tablename WHERE col1name =|<|> value1 AND|OR col2name =|<|> value2  |" << endl;
    cout << "| 6. Sum column              | SELECT SUM(colname) FROM tablename WHERE col1name =|<|> value AND|OR col2name =|<|> value              |" << endl;
    cout << "| 7. Multiply column(no need)| SELECT MULT(colname) FROM tablename WHERE col1name =|<|> value AND|OR col2name =|<|> value             |" << endl;
    cout << "+----------------------------+--------------------------------------------------------------------------------------------------------+" << endl;
}
// funciton that constructs the query string to be sent
string create_query(int input_opt, vector<string> *val_to_encrypt, int *query_num)
{
    int input;
    string tablename, col_name, col_val, col_op, row_num, and_or;
    string comm, comm1;

    if (input_opt == 1)
    {
        cout << "Input message: ";
        cin.ignore();
        getline(cin, comm);
        return comm;
    }
    else if (input_opt == 0)
    {
        cout << "Choose Query (1 to 6): ";
        cin >> input;
        *query_num = input;
        switch (input)
        {
        case 1:
            cout << "Table Name: ";
            cin >> tablename;

            comm = "CREATE TABLE ";
            comm.append(tablename);
            comm.append(" (");

            // construct query
            while (true)
            {
                cout << "Column Name('end' to terminate): ";
                cin >> col_name;
                if (col_name.compare("end") == 0)
                    break;

                comm.append(col_name);
                comm.append(" ");
            }
            comm.append(")");

            break;
        case 2:
            cout << "Table Name: ";
            cin >> tablename;

            comm = "INSERT INTO TABLE ";
            comm.append(tablename);
            comm.append(" (");

            comm1 = "VALUES ";

            // construct query
            while (true)
            {
                cout << "Column Name('end' to terminate): ";
                cin >> col_name;
                if (col_name.compare("end") == 0)
                    break;

                cout << "Column Value: ";
                cin >> col_val;

                // add value to list of values
                (*val_to_encrypt).insert((*val_to_encrypt).end(), col_val);
                comm.append(col_name);
                comm.append(" ");
                comm1.append(" % ");
            }
            comm.append(") ");
            comm.append(comm1);

            break;
        case 3:
            cout << "Table Name: ";
            cin >> tablename;

            cout << "Row Number: ";
            cin >> row_num;

            comm = "DELETE ";
            comm.append(row_num);
            comm.append(" FROM ");
            comm.append(tablename);

            break;
        case 4:
            cout << "Table Name: ";
            cin >> tablename;

            cout << "Row Number: ";
            cin >> row_num;

            comm = "SELECT ROW ";
            comm.append(row_num);
            comm.append(" FROM ");
            comm.append(tablename);

            break;
        case 5:
            cout << "Table Name: ";
            cin >> tablename;

            comm = "SELECT ";
            while (true)
            {
                cout << "Column Name('end' to terminate): ";
                cin >> col_name;
                if (col_name.compare("end") == 0)
                    break;

                comm.append(col_name);
                comm.append(" ");
            }

            comm.append("FROM ");
            comm.append(tablename);
            comm.append(" WHERE ");

            cout << comm << endl;

            while (true)
            {
                cout << "Column Name: ";
                cin >> col_name;
                cout << "Operand(=, < or >): ";
                cin >> col_op;
                cout << "Column Value: ";
                cin >> col_val;

                (*val_to_encrypt).insert((*val_to_encrypt).end(), col_val);
                comm.append(col_name);
                comm.append(" ");
                comm.append(col_op);
                comm.append(" ");
                comm.append("% ");

                cout << "Next Comparation ('end' to terminate): ";
                cin >> and_or;
                if(and_or.compare("end") != 0){
                    comm.append(and_or);
                    comm.append(" ");
                } 
                else break;
            }
            break;
        case 6:
            cout << "Table Name: ";
            cin >> tablename;

            cout << "Column Name: ";
            cin >> col_name;

            comm = "SELECT SUM(";
            comm.append(col_name);
            comm.append(") FROM ");
            comm.append(tablename);
            comm.append(" WHERE ");

            cout << comm << endl;

            while (true)
            {
                cout << "Column Name: ";
                cin >> col_name;
                cout << "Operand(=, < or >): ";
                cin >> col_op;
                cout << "Column Value: ";
                cin >> col_val;

                (*val_to_encrypt).insert((*val_to_encrypt).end(), col_val);
                comm.append(col_name);
                comm.append(" ");
                comm.append(col_op);
                comm.append(" ");
                comm.append("% ");

                cout << "Next Comparation ('end' to terminate): ";
                cin >> and_or;
                if(and_or.compare("end") != 0){
                    comm.append(and_or);
                    comm.append(" ");
                } 
                else break;
            }
        }
    }
    else
        return "erro";

    cout << "\nCommand: " << comm << endl;
    return comm;
}

int hex_to_dec(Plaintext hexadecimal){
    int decimal;
    
    std::stringstream ss;
    ss  <<  hexadecimal.to_string(); // std::string hex_value
    ss >> hex >> decimal; //int decimal_value

    return decimal;
}

/********************************************* Client Main **************************************************/

int main(int argc, char *argv[])
{
    cout << "Welcome! To access and change the database choose from the following commands\n"
         << endl;

    bool run = true;
    int val_flag;
    string message, message_values_encoded, message_encoded;
    string reply, reply_decoded, reply_values_decoded;
    int input_opt;
    int query_num;
    
    vector<string> val_to_encrypt {};

    bool verify = verify_documents();
    if (!verify)
        return EXIT_FAILURE;

    while (run)
    {
        // prints the server's API possible commands
        print_commands();

        cout << "Construct Query (0), Input by Hand (1): ";
        cin >> input_opt;

        val_to_encrypt = {};
        message = create_query(input_opt, &val_to_encrypt, &query_num);
        while (message.compare("erro") == 0){message = create_query(input_opt, &val_to_encrypt, &query_num);}
        
        // flag = 0 if there are no values to encrypt else flag = 1
        if(val_to_encrypt.size() == 0) val_flag = 0;
        else val_flag = 1;

        // only encodes values if there is values to encode
        if(val_flag) encode_values(val_to_encrypt);

        encode_message(message, val_flag);

        while (run && (query_num == 4 || query_num == 5 || query_num == 6) ){
            string check = exec("if    ls -1qA Answers/ | grep -q .; then  ! echo not empty; else  echo empty; fi");
            if (check.compare("empty\n") != 0) break;
        }

        decode_message(query_num);

        if(query_num == 4 || query_num == 5 || query_num == 6) decode_values();
    }
    return EXIT_SUCCESS;
}