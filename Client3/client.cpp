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

    // extract server's public key from certificate
    system("openssl x509 -pubkey -noout -in Files/Server-cert.crt > Files/Server-publ.pem\n");
    // generate random password file
    system("openssl rand -base64 32 > session.key\n");
    
    // session key signed with client's private key
    system("openssl dgst -sha256 -sign Files/Client3-priv.pem -out Files/Client3-sign.sha256 session.key");
    // session key encrypted with server's public key
    system("openssl rsautl -encrypt -pubin -inkey Files/Server-publ.pem -in session.key -out Files/Client3-session.key.enc\n");

    // signature of session key encrypted with server's public key
    //system("openssl rsautl -encrypt -pubin -inkey Files/Server-publ.pem -in Files/Client3-sign.sha256 -out Files/Client3-sign.sha256.enc\n");
    
    // encrypt message with session key
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/Client3-sign.sha256 -out Files/Client3-sign.sha256.enc -pass file:./session.key\n");

    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/message.txt -out Files/Client3-message.enc -pass file:./session.key\n");
    if(val_flag) system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/values.txt -out Files/Client3-values.enc -pass file:./session.key\n");

    // remove unnecessary files
    system("rm Files/message.txt\n");
    if(val_flag) system("rm Files/values.txt\n");

    // moves encoded session-key, encoded message and certificate to server's folder
    system("mv Files/Client3-message.enc ../Server/Messages\n");
    if(val_flag) system("mv Files/Client3-values.enc ../Server/Messages\n");
    system("mv Files/Client3-session.key.enc ../Server/Messages\n");
    system("mv Files/Client3-sign.sha256.enc ../Server/Messages\n");
    system("cp Files/Client3-cert.crt ../Server/Messages\n");
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
    system("openssl verify -CAfile Files/root_ca.crt Files/Client3-cert.crt > Files/verified.txt");
    // load verified.txt to confirm signature
    string sign_check = load_string("Files/verified.txt");
    system("rm Files/verified.txt\n");

    if (sign_check.find("Files/Client3-cert.crt: OK") != 0)
    {
        cout << "Client certificate is not valid! Message will not be considered" << endl;
        return false;
    }

    // check if client certificate has expired
    string exp_date = exec("openssl x509 -enddate -noout -in Files/Client3-cert.crt");    
    tm current_time = get_time();

    string check_date = verify_date(exp_date, current_time);
    if (check_date.compare("NOK") == 0) return false;

    // check if server certificate is valid
    system("openssl verify -CAfile Files/root_ca.crt Files/Server-cert.crt > Files/verified.txt");
    // load verified.txt to confirm signature
    sign_check = load_string("Files/verified.txt");
    system("rm Files/verified.txt\n");

    if (sign_check.find("Files/Server-cert.crt: OK") != 0)
    {
        cout << "Server certificate is not valid! Message will not be considered" << endl;
        return false;
    }

    // check if server certificate has expired
    exp_date = exec("openssl x509 -enddate -noout -in Files/Server-cert.crt");    
    current_time = get_time();

    check_date = verify_date(exp_date, current_time);
    if (check_date.compare("NOK") == 0) return false;


    // check if client's private key is coherent with clients certificate
    string crt = exec("openssl x509 -noout -modulus -in Files/Client3-cert.crt| openssl md5");
    string key = exec("openssl rsa -noout -modulus -in Files/Client3-priv.pem | openssl md5");

    if (crt.compare(key))
    {
        cout << "Client's private key doesn't match with certificate" << endl;
        return false;
    }
    
    // verify public database key signature
    sign_check = exec("openssl dgst -sha256 -verify Files/root-publ.key -signature Files/DB_public.sha256 Files/DB_public.key");
    if (sign_check.compare("Verified OK\n") == 0) cout << "Public DB Key Signature Validation: " << sign_check << endl;
    else{
        cout << "Signature not valid! Message will not be considered" << endl;
        return false;
    }

    // verify private database key signature
    sign_check = exec("openssl dgst -sha256 -verify Files/root-publ.key -signature Files/DB_private.sha256 Files/DB_private.key");
    if (sign_check.compare("Verified OK\n") == 0) cout << "Private DB Key Signature Validation: " << sign_check << endl;
    else{
        cout << "Signature not valid! Message will not be considered" << endl;
        return false;
    }
    
    return true;
}
// function to decode message with private and public key
void decode_message(int flag_error)
{   
    if (flag_error){
        system("openssl enc -d -aes-256-cbc -pbkdf2 -in Answers/fail.enc -out Answers/fail.txt -pass file:./session.key\n");
        string fail = load_string("Answers/fail.txt");
        cout << fail << endl;
        
        system("rm Answers/fail.enc Answers/fail.txt");

        return;
    } 
    // descrypt message with session key
    system("openssl enc -d -aes-256-cbc -pbkdf2 -in Answers/query_result.enc -out Answers/query_result.txt -pass file:./session.key\n");
    system("openssl enc -d -aes-256-cbc -pbkdf2 -in Answers/query_result_2.enc -out Answers/query_result_2.txt -pass file:./session.key\n");

    system("rm Answers/query_result.enc Answers/query_result_2.enc");
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
    cout << "+----------------------------+--------------------------------------------------------------------------------------------------------+" << endl;
}
// funciton that constructs the query string to be sent
string create_query(vector<string> *val_to_encrypt, int *query_num)
{
    int input, col_val, row_num;
    string tablename, col_name, col_op, and_or;
    string comm, comm1;
    cout << "Choose Query (1 to 6) or '0' to quit: ";
    cin >> input;
    while(cin.fail()) {
        cout << "That option is not available.\n";
        cin.clear();
        cin.ignore(256,'\n');
        cout << "Choose Query (1 to 6) or '0' to quit: ";
        cin >> input;
    }
    *query_num = input;

    switch (input){
        case 0:
        return "exit";
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

                while(cin.fail()) {
                    cout << "Please enter a number.\n";
                    cin.clear();
                    cin.ignore(256,'\n');
                    cout << "Column Value: ";
                    cin >> col_val;
                }

                // add value to list of values
                (*val_to_encrypt).insert((*val_to_encrypt).end(), to_string(col_val));
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
            while(cin.fail()) {
                cout << "Please enter a number.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Row Number: ";
                cin >> row_num;
                }
            
            comm = "DELETE ";
            comm.append(to_string(row_num));
            comm.append(" FROM ");
            comm.append(tablename);

            break;
        case 4:
            cout << "Table Name: ";
            cin >> tablename;

            cout << "Row Number: ";
            cin >> row_num;
            while(cin.fail()) {
                cout << "Please enter a number.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Row Number: ";
                cin >> row_num;
                }
            comm = "SELECT ROW ";
            comm.append(to_string(row_num));
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

            // First comparasion
            cout << comm << endl;
            cout << "Column Name: ";
            cin >> col_name;
            cout << "Operand(=, < or >): ";
            cin >> col_op;
            while(col_op.compare(">") != 0 && col_op.compare("<") != 0 && col_op.compare("=") != 0){
                cout << "Please enter a valid operand.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Operand(=, < or >): ";
                cin >> col_op;
            }
            cout << "Column Value: ";
            cin >> col_val;
            while(cin.fail()) {
                cout << "Please enter a number.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Column Value: ";
                cin >> col_val;
            }
            (*val_to_encrypt).insert((*val_to_encrypt).end(), to_string(col_val));
            comm.append(col_name);
            comm.append(" ");
            comm.append(col_op);
            comm.append(" ");
            comm.append("% ");

            // Logic comparador
            cout << "Next Comparation ('AND' or 'OR'): ";
            cin >> and_or;
            while(and_or != "AND" && and_or != "OR"){
                cout << "Please write AND or OR): ";
                cin >> and_or;
            }
            comm.append(and_or);
            comm.append(" ");

            // Second comparasion
            cout << "Column Name: ";
            cin >> col_name;
            cout << "Operand(=, < or >): ";
            cin >> col_op;
            while(col_op.compare(">") != 0 && col_op.compare("<") != 0 && col_op.compare("=") != 0){
                cout << "Please enter a valid operand.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Operand(=, < or >): ";
                cin >> col_op;
            }
            cout << "Column Value: ";
            cin >> col_val;
            while(cin.fail()) {
                cout << "Please enter a number.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Column Value: ";
                cin >> col_val;
            }
            (*val_to_encrypt).insert((*val_to_encrypt).end(), to_string(col_val));
            comm.append(col_name);
            comm.append(" ");
            comm.append(col_op);
            comm.append(" ");
            comm.append("% ");

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

            // First comparasion
            cout << "Column Name: ";
            cin >> col_name;
            cout << "Operand(=, < or >): ";
            cin >> col_op;
            while(col_op.compare(">") != 0 && col_op.compare("<") != 0 && col_op.compare("=") != 0){
                cout << "Please enter a valid operand.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Operand(=, < or >): ";
                cin >> col_op;
            }
            cout << "Column Value: ";
            cin >> col_val;
            while(cin.fail()) {
                cout << "Please enter a number.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Column Value: ";
                cin >> col_val;
            }
            (*val_to_encrypt).insert((*val_to_encrypt).end(), to_string(col_val));
            comm.append(col_name);
            comm.append(" ");
            comm.append(col_op);
            comm.append(" ");
            comm.append("% ");

            // Logic comparador
            cout << "Next Comparation ('AND' or 'OR'): ";
            cin >> and_or;
            while(and_or != "AND" && and_or != "OR"){
                cout << "Please write AND or OR): ";
                cin >> and_or;
            }
            comm.append(and_or);
            comm.append(" ");

            // Second comparasion
            cout << "Column Name: ";
            cin >> col_name;
            cout << "Operand(=, < or >): ";
            cin >> col_op;
            while(col_op.compare(">") != 0 && col_op.compare("<") != 0 && col_op.compare("=") != 0){
                cout << "Please enter a valid operand.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Operand(=, < or >): ";
                cin >> col_op;
            }
            cout << "Column Value: ";
            cin >> col_val;
            while(cin.fail()) {
                cout << "Please enter a number.\n";
                cin.clear();
                cin.ignore(256,'\n');
                cout << "Column Value: ";
                cin >> col_val;
            }
            (*val_to_encrypt).insert((*val_to_encrypt).end(), to_string(col_val));
            comm.append(col_name);
            comm.append(" ");
            comm.append(col_op);
            comm.append(" ");
            comm.append("% ");
            break;

        default:
            cout << "That option is not available.\n";
            return "erro";
        }
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
    int query_num;
    
    vector<string> val_to_encrypt {};

    bool verify = verify_documents();
    if (!verify)
        return EXIT_FAILURE;

    while (run)
    {
        // prints the server's API possible commands
        print_commands();
        val_to_encrypt = {};

        message = "erro";
        while (message.compare("erro") == 0){message = create_query(&val_to_encrypt, &query_num);}
        if (message == "exit"){
            run = 0;
            break;
        }
        
        // flag = 0 if there are no values to encrypt else flag = 1
        if(val_to_encrypt.size() == 0) val_flag = 0;
        else val_flag = 1;

        // only encodes values if there is values to encode
        if(val_flag){
            cout << "Encrypting query values..." << endl;
            encode_values(val_to_encrypt);
        } 

        cout << "Encrypting, Signing and Sending query..." << endl;
        encode_message(message, val_flag);
        
        if (query_num == 4 || query_num == 5 || query_num == 6){
            cout << "Waiting for server answer..." << endl;
            while (run){
                string check = exec("if    ls -1qA Answers/ | grep -q .; then  ! echo not empty; else  echo empty; fi");
                if (check.compare("empty\n") != 0) break;
            }
        }
        
        if(query_num == 4 || query_num == 5 || query_num == 6){
            string filename = exec("cd Answers/\nls -1 | head -n 1");
            if (filename.compare("fail.enc\n") == 0){
				decode_message(1);
			}
            else{
                cout << "Decrypting query answer..." << endl;
                decode_message(0);    
                cout << "Decrypting query values..." << endl;
                decode_values();
            }
        } 
        else{
            sleep(5);
            string filename = exec("cd Answers/\nls -1 | head -n 1");
            if (filename.compare("fail.enc\n") == 0){
                decode_message(1);
            }
        }

        cout << "Deleting Session Key..." << endl;
        system("rm session.key");
    }
    return EXIT_SUCCESS;
}