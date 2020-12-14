#include "../resources.h"


/******************************************** OpenSSL functions *********************************************/

bool verify_root_CA()
{
    string root_id;

    ifstream root("Files/root_ca.crt");
    if (!root.fail())
    {

        system("openssl x509 -in Files/root_ca.crt -noout -pubkey > Files/root-publ.key\n");
        system("openssl x509 -noout -subject -in Files/root_ca.crt | sed -n 's/.*CN = \\([^,]*\\).*/\\1/p' > Files/root_id.txt\n");
        root_id = load_string("Files/root_id.txt");

        if (root_id.compare("root\n") == 0)
        {
            root.close();
            system("rm Files/root_id.txt\n");
            return true;
        }
        else
        {
            root.close();
            cout << "CA inválido: não corresponde à root\n";
        }
    }
    return false;
}

int verify_client_sign(string name)
{

    // extract client's public key from certificate
    string comm("openssl x509 -pubkey -noout -in Files/");
    comm.append(name);
    comm.append("-cert.crt > Files/");
    comm.append(name);
    comm.append("-publ.pem\n\n");

    const char *run_comm = comm.c_str();
    system(run_comm);

    // verify encrypted session key signature
    comm = "openssl dgst -sha256 -verify Files/";
    comm.append(name);
    comm.append("-publ.pem -signature Files/");
    comm.append(name);
    comm.append("-sign.sha256 Files/");
    comm.append(name);
    comm.append("-session.key.enc > Files/verified.txt\n");

    const char *run_comm2 = comm.c_str();
    system(run_comm2);

    // remove unecessary files - encrypted sesion key
    comm = "rm Files/";
    comm.append(name);
    comm.append("-session.key.enc");

    const char *run_comm3 = comm.c_str();
    system(run_comm3);

    // load verified.txt to confirm signature
    string sign_check = load_string("Files/verified.txt");
    cout << "\nSignature Validation: " << sign_check << endl;

    system("rm Files/verified.txt\n");

    if (sign_check.compare("Verified OK\n") == 0)
    {
        cout << "\nSignature is valid!" << endl;
        return true;
    }
    else
    {
        cout << "\nerror: Signature not valid! Message will not be considered" << endl;
        return false;
    }
}

string decode_query(string name)
{

    // descrypt session key with server's private key
    string comm("openssl rsautl -decrypt -inkey Files/Server-priv.pem -in Files/");
    comm.append(name);
    comm.append("-session.key.enc -out session.key\n");

    const char *run_comm = comm.c_str();
    system(run_comm);

    // descrypt message with session key
    comm = "openssl enc -d -aes-256-cbc -pbkdf2 -in Files/";
    comm.append(name);
    comm.append("-message.enc -out Files/message.txt -pass file:./session.key\n");

    const char *run_comm2 = comm.c_str();
    system(run_comm2);

    // remove unecessary files - encoded message with session key
    comm = "rm Files/";
    comm.append(name);
    comm.append("-message.enc\n");

    const char *run_comm3 = comm.c_str();
    system(run_comm3);

    // import message into variable
    string message_decoded = load_string("Files/message.txt");
    cout << "\nMessage decoded: " << message_decoded << endl;

    return message_decoded;
}

void encode_message(string query_result, string name)
{

    // encrypt query result with session key
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/query_result.txt -out Files/query_result.enc -pass file:./session.key\n");
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/query_result_2.txt -out Files/query_result_2.enc -pass file:./session.key\n");

    // moves encoded file to client folder
    string comm("mv Files/query_result.enc Files/query_result_2.enc ../");
    comm.append(name);
    comm.append("/Files\n");

    const char *run_comm = comm.c_str();
    system(run_comm);

    // remove unnecessary files: session key and plain-text messages
    system("rm session.key\n rm Files/query_result.txt \n rm Files/query_result_2.txt");
}

void decode_values_message(string name)
{
    // descrypt message with session key
    string comm("openssl enc -d -aes-256-cbc -pbkdf2 -in Files/");
    comm.append(name);
    comm.append("-values.enc -out Files/values.txt -pass file:./session.key\n");

    const char *run_comm2 = comm.c_str();
    system(run_comm2);

    // remove unecessary files - encoded message with session key
    comm = "rm Files/";
    comm.append(name);
    comm.append("-values.enc\n");

    const char *run_comm3 = comm.c_str();
    system(run_comm3);
}

/******************************************** SEAL functions ************************************************/

Ciphertext NOT(Ciphertext input, Evaluator *eval)
{
    int i = 1;
    Ciphertext output;
    Plaintext i_plain(to_string(i));
    (*eval).negate_inplace(input);
    (*eval).add_plain(input, i_plain, output);
    //     Nº -> Simétrico -> +1
    // Caso A: 1 -> -1 -> 0
    // Caso B: 0 -> 0 -> 1

    return output;
}

Ciphertext AND(Ciphertext inA, Ciphertext inB, Evaluator *eval) /*Should be single bits - effectively a multiplication*/
{
    Ciphertext mult_result;
    (*eval).multiply(inA, inB, mult_result);

    return mult_result;
}

Ciphertext OR(Ciphertext inA, Ciphertext inB, Evaluator *eval, RelinKeys relin_keys)
{
    Ciphertext or_result, sum_result, and_result;

    (*eval).add(inA, inB, sum_result);
    and_result = AND(inA, inB, eval);
    (*eval).relinearize_inplace(and_result, relin_keys);
    (*eval).sub(sum_result, and_result, or_result);

    /*Soma de 2 números representando bits mas efetivamente decimais.
  Não existe soma lógica - adaptação de soma e multiplicação aritméticass
  | A | B | Soma | Mult (AND) | Soma-mult = OR
  | 0 | 0 |  0   |     0      |        0
  | 0 | 1 |  1   |     0      |        1
  | 1 | 0 |  1   |     0      |        1
  | 1 | 1 |  2   |     1      |        1  */

    return or_result;
}

vector<Ciphertext> bit_Comparator(Ciphertext inA, Ciphertext inB, vector<Ciphertext> rolling, RelinKeys relin_keys, Evaluator *eval)
{
    Ciphertext B_greater_A, A_greater_B, A_equal_B;

    B_greater_A = AND(NOT(inA, eval), inB, eval);
    (*eval).relinearize_inplace(B_greater_A, relin_keys);

    A_greater_B = AND(inA, NOT(inB, eval), eval);
    (*eval).relinearize_inplace(A_greater_B, relin_keys);

    A_equal_B = NOT(OR(A_greater_B, B_greater_A, eval, relin_keys), eval);

    if (rolling.empty()) /*First numbers*/
    {
        rolling.push_back(A_equal_B);   //rolling[0]
        rolling.push_back(A_greater_B); //rolling[1]
        rolling.push_back(B_greater_A); //rolling[2]
    }
    else
    {
        rolling.at(0) = AND(A_equal_B, rolling.at(0), eval);
        (*eval).relinearize_inplace(rolling.at(0), relin_keys);
        rolling.at(1) = AND(OR(A_greater_B, rolling.at(1), eval, relin_keys), NOT(rolling.at(2), eval), eval);
        (*eval).relinearize_inplace(rolling.at(1), relin_keys);
        rolling.at(2) = AND(OR(B_greater_A, rolling.at(2), eval, relin_keys), NOT(rolling.at(1), eval), eval);
        (*eval).relinearize_inplace(rolling.at(2), relin_keys);
    }

    return rolling;
}

vector<Ciphertext> Full_comparator(vector<Ciphertext> A, vector<Ciphertext> B, RelinKeys relin_keys, Evaluator *eval)
{
    vector<Ciphertext> results;
    int size = A.size();
    int i;

    if (A.size() != B.size())
    {
        cout << "Erro - tamanhos diferentes\n";
        exit(1);
    }
    /*From MSB to LSB*/
    results = bit_Comparator(A.at(size - 1), B.at(size - 1), results, relin_keys, eval);
    for (i = size - 2; i >= 0; i--)
    {
        results = bit_Comparator(A.at(i), B.at(i), results, relin_keys, eval);
    }

    return results;
}

SEALContext create_context()
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(64);
    SEALContext context(parms);

    return context;
}

/***************************************** Client Aux Functions *********************************************/

void create_database()
{

    if (system("[ -d 'Encrypted_Database' ]"))
    { //if not exists - create directory
        system("mkdir Encrypted_Database");
        cout << "Database created!\n";
    }
    else
    {
        cout << "Database already exists!\n";
    }
}

int check_exists_table(string name)
{

    string tbl("cd Encrypted_Database\n[ -d '");
    tbl.append(name);
    tbl.append("' ]");
    const char *table = tbl.c_str();
    if (system(table))
    {
        string tbl("cd Encrypted_Database\n mkdir ");
        tbl.append(name);
        const char *table = tbl.c_str();
        system(table);
        cout << "Created table!\n";
        return 1;
    }
    else
    {
        cout << "Table already exists !\n";
        return 0;
    }
}

void create_clients_file(string name)
{
    string filename("");
    filename.append(name);
    filename.append("_clients.txt");

    //directory to create the file
    string path1("/home/catarinamaro/Documents/Técnico/Cripto/CSC_Project/Server/Encrypted_Database/");
    path1.append(name);
    path1.append("/");
    path1.append(filename);

    ofstream myfile(path1);

    string data("Clients that have access to this table:");
    myfile << data;
    myfile.close();
}

void create_column(string name, string column)
{
    string tbl("cd Encrypted_Database\n cd ");
    tbl.append(name);
    tbl.append("\n");
    tbl.append(" mkdir ");
    tbl.append(column);
    tbl.append("\n");
    const char *col = tbl.c_str();
    system(col);

    /*string filename ("");
    filename.append(column);
    filename.append("_data.txt");
    //directory to create the file
    string path1("/home/catarinamaro/Documents/Técnico/Cripto/CSC_Project/Server/Encrypted_Database/");
    path1.append(name);
    path1.append("/");
    path1.append(column);
    path1.append("/");
    path1.append(filename);
    ofstream myfile(path1);
    //myfile.open(filename);
    string data("INT");
    myfile << data;
    myfile.close();*/
}

int create_table(string message)
{

    string word = "";
    string name = "";
    int i = 1;
    int j = 0;
    int get_col = 0;
    vector<string> colnames(10);
    //Get name of the table and the columns
    for (auto x : message)
    {
        if (x == '(')
        {
            word = "";
            get_col = 1;
        }
        else if (x == ')')
            break;

        else if (x == ' ')
        {
            if (i == 3)
            {
                cout << "Table name is " + word << endl;
                name = word;
                i = 100;
            }
            if (get_col)
            {
                colnames.insert(colnames.end(), word.c_str());
                j += 1;
                word = "";
            }
            word = "";
            i += 1;
        }
        else
            word = word + x;
    }

    if (i == 3)
    {
        cout << "Table name is " + word << endl;
        name = word;
    }
    //remove \n
    if (!name.empty() && name[name.length() - 1] == '\n')
        name.erase(name.length() - 1);

    // Check if table already exists, if not, create
    check_exists_table(name);

    //Creating name of the file that contains clients ID
    create_clients_file(name);

    //Creating columns
    for (int k = 0; k < colnames.size(); k++)
    {
        if (colnames.at(k).compare("") != 0)
        {
            cout << colnames.at(k) << endl;
            create_column(name, colnames.at(k));
        }
    }
    return 1;
}

vector<string> check_query_names(string message_decoded, string *tablename, string command, int *row_num, vector<string> *colnames_op, vector<int> *logic, vector<int> *operators)
{
    vector<string> colnames = {};
    string s = message_decoded, delimiter = " ", token;

    size_t pos = 0, i = 1;
    while ((pos = s.find(delimiter)) != string::npos)
    {
        token = s.substr(0, pos);
        s.erase(0, pos + delimiter.length());

        if (i == 2 && command.compare("DELETE") == 0)
            *row_num = stoi(token);
        else if (i == 3 && command.compare("SELECT ROW") == 0)
            *row_num = stoi(token);
        else if (command.compare("INSERT") == 0){
            if (i == 4) *tablename = token;
            else if (i == 5){
                token.erase(0, 1);
                while (token.compare(")") != 0 && (pos = s.find(delimiter)) != string::npos)
                {
                    colnames.insert(colnames.end(), token);
                    token = s.substr(0, pos);
                    s.erase(0, pos + delimiter.length());
                }
            }
        }
        else if (command.compare("SELECT") == 0)
        {
            if(i==2){
                while (token.compare("FROM") != 0 && (pos = s.find(delimiter)) != string::npos)
                {
                    colnames.insert(colnames.end(), token);
                    token = s.substr(0, pos);
                    s.erase(0, pos + delimiter.length());
                }
            }
            else if (i == 3) *tablename = token;
            else if (i == 5) (*colnames_op).insert((*colnames_op).end(), token);
            else if (i == 6){
                if(token.compare("=")==0) (*operators).insert((*operators).end(), 0);
                else if(token.compare(">")==0) (*operators).insert((*operators).end(), 1);
                else if(token.compare("<")==0) (*operators).insert((*operators).end(), 2);
            }
            else if (i == 8){
                //logic
                if(token.compare("AND")==0) (*logic).insert((*logic).end(), 0);
                else if(token.compare("OR")==0) (*logic).insert((*logic).end(), 1);
                i = 4;
            }
        }
        else if (command.compare("SUM") == 0){
            if (i == 2){
                token.erase(0, 4);
                token.erase(token.length()-1, 1);
                colnames.insert(colnames.begin(), token);
                cout << "Col name is " + colnames.at(0) << endl;
            }
            else if (i == 4)*tablename = token;
            else if (i == 5){
                i = 4;
                command = "SELECT";
            } 
        }

        i++;
    }
    if (command.compare("DELETE") == 0 || command.compare("SELECT ROW") == 0)
        (*tablename) = s;

    (*tablename).erase(remove((*tablename).begin(), (*tablename).end(), '\n'), (*tablename).end());

    cout << "Table name is " + (*tablename) << endl;
    cout << "Table row is " + to_string(*row_num) << endl;

    if (check_exists_table(*tablename) != 0)
    {
        cout << "Table does not exist" << '\n';
        return {"FAILURE"};
    }

    if (colnames.size() == 0)
        colnames = {"SUCCESS"};
    return colnames;
}

string execute_query(string message_decoded, string client_name)
{
    vector<string> colnames_op = {};
    vector<int> logic = {};
    vector<int> operators = {};
    vector<string> colnames(10);
    string tablename("");
    int row_num = -1;
    
    if (message_decoded.find("CREATE TABLE") == 0)
    {
        cout << "Found CREATE TABLE!" << '\n';
        create_table(message_decoded);
        return "CREATE";
    }
    else if (message_decoded.find("INSERT") == 0)
    {
        cout << "Found INSERT!" << '\n';
        colnames = check_query_names(message_decoded, &tablename, "INSERT", &row_num, {}, {}, {});
        if (colnames.size() == 0)
            return "FAILURE";

        int n_values = count(message_decoded.begin(), message_decoded.end(), '%');

        decode_values_message(client_name);

        insert_values(n_values, tablename, colnames);

        return "INSERT";
    }
    else if (message_decoded.find("DELETE") == 0)
    {
        cout << "Found DELETE!" << '\n';
        vector<string> ret;

        ret = check_query_names(message_decoded, &tablename, "DELETE", &row_num, {}, {}, {});
        if (ret.size() == 0)
            return "FAILURE";

        delete_line(row_num, tablename);

        return "DELETE";
    }
    else if (message_decoded.find("SELECT ROW") == 0)
    {
        cout << "Found SELECT ROW!" << '\n';

        check_query_names(message_decoded, &tablename, "SELECT ROW", &row_num, {}, {}, {});

        select_line(tablename, row_num);
        return "SELECT";
    }
    else if (message_decoded.find("SELECT SUM") == 0)
    {
        cout << "Found SELECT SUM!" << '\n';
    
        colnames = check_query_names(message_decoded, &tablename, "SUM", &row_num, &colnames_op, &logic, &operators);
        return "SELECT";
    }
    else if (message_decoded.find("SELECT") == 0)
    {
        cout << "Found SELECT!" << '\n';
        
        int operation;
        // pôr logo no ficheiro em vez de num vector de ciphertext

        colnames = check_query_names(message_decoded, &tablename, "SELECT", &row_num, &colnames_op, &logic, &operators); //NEED OPERATOR
        for(int i=0; i<colnames_op.size(); i++){
            cout << "Colnames " << colnames_op.at(i) << endl;
            cout << "Operators:" << operators.at(i) << endl;
            if (i != colnames_op.size()-1) cout << "Logic:" << logic.at(i) << endl;
        }
         
        select(colnames, tablename, operation);

        return "SELECT";
        //ESCREVER PARA FICHEIRO/ENCRIPTAR COM SESSION KEYS
    }
    else
    {
        cout << "Command not found!" << '\n';
    }

    return "FAILURE";
}

void send_reply(int newFD, string reply)
{
    // message to alert client that the answer is already the files directory
    auto bytes_sent = send(newFD, &reply.front(), reply.length(), 0);

    cout << "\nSent message: " << reply << endl;
    // ends communication between client and server
    close(newFD);
}

/***************************************** Query Functions *********************************************/

void insert_values(int n_value, string tablename, vector<string> colname)
{
    SEALContext context = create_context();

    vector<Ciphertext> value_encrypted(9);

    ifstream values_file;
    values_file.open("Files/values.txt", ios::binary);

    string path("Encrypted_Database/");
    path.append(tablename);
    path.append("/");
    path.append(colname.at(0));

    string comm("cd ");
    comm.append(path);
    comm.append("\nls -1 | tail -n 2 > last_row.bin");

    const char *run_comm = comm.c_str();
    system(run_comm);

    string row_path(path);
    path.append("/last_row.bin");

    ifstream last_row_file(path);
    string last_row_name;

    getline(last_row_file, last_row_name);
    last_row_file.close();
    comm = "rm ";
    comm.append(path);

    const char *run_comm1 = comm.c_str();
    system(run_comm1);

    int last_row;
    if (last_row_name.compare("last_row.bin") == 0)
        last_row = -1;
    else
        last_row = last_row_name.at(0) - '0';

    for (int i = 0; i < n_value; i++)
    {
        string file_path("Encrypted_Database/");
        file_path.append(tablename);
        file_path.append("/");
        file_path.append(colname.at(i));
        file_path.append("/");
        file_path.append(to_string(last_row + 1));
        file_path.append(".txt");

        ofstream entry_file;
        entry_file.open(file_path, ios::binary);
        value_encrypted.at(0).load(context, values_file);
        value_encrypted.at(0).save(entry_file);

        for (int i = 1; i < 9; i++)
        {
            value_encrypted.at(i).load(context, values_file);
            value_encrypted.at(i).save(entry_file);
        }

        entry_file.close();
    }
}

void delete_line(int row_num, string tablename)
{
    string comm("rm Encrypted_Database/");
    comm.append(tablename);
    comm.append("/*/");
    comm.append(to_string(row_num));
    comm.append(".txt");

    const char *run_comm = comm.c_str();
    system(run_comm);
}

void select_line(string tablename, int row_num)
{

    /************** get column names *****************/
    string path("Encrypted_Database/");
    path.append(tablename);
    path.append("/");

    string comm("cd ");
    comm.append(path);
    comm.append("\n for d in */ ; do  echo \"$d\" >> col_name.bin; done");

    const char *run_comm = comm.c_str();
    system(run_comm);

    string file_path = path;
    ifstream col_file(file_path.append("col_name.bin"));
    vector<string> col_name = {};
    string aux;

    int i = 0;
    while (getline(col_file, aux))
    {
        col_name.insert(col_name.end(), aux);
        cout << col_name.at(i) << endl;
        i++;
    }

    col_file.close();
    comm = "rm ";
    comm.append(file_path);

    const char *run_comm1 = comm.c_str();
    system(run_comm1);

    /************** get values into single file to be sent *****************/
    SEALContext context = create_context();
    vector<Ciphertext> value_encrypted(9);

    ofstream result_file;
    result_file.open("Files/query_result.txt", ios::binary);

    for (int j = 0; j < col_name.size(); j++)
    {
        string value_path = path;
        value_path.append(col_name.at(j)); //Não falta barras?
        value_path.append(to_string(row_num));
        value_path.append(".txt");

        ifstream entry_file;
        entry_file.open(value_path, ios::binary);

        value_encrypted.at(0).load(context, entry_file);
        value_encrypted.at(0).save(result_file);

        for (int i = 1; i < 9; i++)
        {
            value_encrypted.at(i).load(context, entry_file);
            value_encrypted.at(i).save(result_file);
        }

        entry_file.close();
    }
    result_file.close();

    ofstream infile("Files/query_result_2.txt");
    // store number of values that is being sent in file
    infile << to_string(col_name.size()) << endl;
    // save column names to send to client
    for (int j = 0; j < col_name.size(); j++)
        infile << col_name.at(j) << endl;

    infile.close();
}

vector<Ciphertext> GetClientInputVal(SEALContext context) //Melhor maneira???
{
    vector<Ciphertext> value_encrypted(8);
    int i = 0;
    ifstream values_file;
    values_file.open("Files/values.txt", ios::binary);
    for (i = 0; i < 8; i++) //C
    {
        value_encrypted.at(0).load(context, values_file);
    }

    return value_encrypted;
}

vector<Ciphertext> select(vector<string> colnames, string tablename, int operation)
{ //operation: 0 if =; 1 if >; 2 if <
    SEALContext context = create_context();
    Evaluator evaluator(context);
    RelinKeys relin_keys;
    KeyGenerator keygen(context);

    keygen.create_relin_keys(relin_keys);
    vector<Ciphertext> compare_results, client_input(9), table_value_bits(8), output_values;
    Ciphertext mult_result, table_value_full;
    int i, j, k, n_of_rows;
    string curr_colname, path;
    ifstream table_value_file, client_values_file;
    ofstream result_file, result_file_2;
    int number_of_rows = 0;

    client_values_file.open("Files/values.txt", ios::binary);

    client_input.at(0).load(context, client_values_file); // Carregar nº completo - para ser overwritten
    for (i = 1; i < 9; i++) //Bits encriptados apenas. Não necessita do nº completo
    {
        client_input.at(i).load(context, client_values_file);
    }

    for (i = 0; i < colnames.size(); i++){
        
    
    // counts number of files inside  column name
    string comm = ("cd Encrypted_Database/");
    comm.append(tablename);
    comm.append("/");
    comm.append(colnames.at(i));
    comm.append("\n ls | wc -l");
    const char *run_comm = comm.c_str();
    number_of_rows = system(run_comm);
    //Select column name.
    curr_colname = colnames.at(i);
      for (j = 0; j < number_of_rows; j++)
      {
        
        //Get Table values
        path = ("Encrypted_Database/");
        path.append(tablename);
        path.append("/");
        path.append(curr_colname);
        path.append("/");
        path.append(to_string(j));
        path.append(".txt");

        table_value_file.open(path, ios::binary);

        table_value_full.load(context, table_value_file); // Primeiro valor completo
        for (k = 0; k < 8; k++) //Depois bit a bit
        {
            table_value_bits.at(k).load(context, table_value_file);
        }

        table_value_file.close();

        compare_results = Full_comparator(client_input, table_value_bits, relin_keys, &evaluator);

        evaluator.multiply(compare_results.at(operation), table_value_full, mult_result);
        output_values.push_back(mult_result);

        //Empty path String
        path.clear();
      }
    }

    //Escrever mult result para ficheiro
    result_file.open("Files/query_result.txt", ios::binary);

    for (i = 0; i < output_values.size(); i++)
    {
        output_values.at(i).save(result_file);
    }
    result_file.close();

    result_file_2.open("Files/query_result_2.txt", ios::binary);
    // store number of values that is being sent in file
    result_file_2 << to_string(output_values.size()) << endl;
    result_file_2.close();


    return output_values;
    //PERGUNTA
    //2 - Necessário dar reset do evaluator?
    //3 - Podemos basear SELECT SUM nisto?
}

vector<Ciphertext> GetTableVal(vector<string> colnames, string tablename, int row_num)
{
    vector<Ciphertext> value_encrypted(9);
    return value_encrypted;
}

/********************************************* Server Main **************************************************/

int main(int argc, char *argv[])
{

    /************************************ setup socket ************************************/

    struct sockaddr_in local_addr;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket: ");
        exit(EXIT_FAILURE);
    }

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(PORT);
    int err = bind(server_fd, (struct sockaddr *)&local_addr,
                   sizeof(local_addr));
    if (err == -1)
    {
        perror("bind: ");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) == -1)
    {
        perror("listen: ");
        exit(EXIT_FAILURE);
    }

    /************************************ setup socket ************************************/

    /*********************************** accept messages **********************************/
    bool run = true;
    string client_name(25, ' '); // stores the client name
    string message_decoded, query_result;

    while (run)
    {
        // accepting messages from clients
        int newFD = accept(server_fd, (sockaddr *)&client_addr, &client_addr_size);
        if (newFD == -1)
        {
            cerr << "Error while Accepting on socket\n";
            continue;
        }

        // receives message that indicates wich client sent files
        auto bytes_received = recv(newFD, &client_name.front(), client_name.length(), 0);
        cout << "\nReceived Query from " << client_name << endl;

        // remove \n from message
        if (!client_name.empty())
            client_name = client_name.substr(0, 7);

        // verify if root certificate is valid
        bool verify = verify_root_CA();
        if (!verify)
        {
            send_reply(newFD, "invalid");
            continue;
        }

        // decode message and session key and saves it in folder
        message_decoded = decode_query(client_name); // query decoded

        // verify if client's signature is valid
        verify = verify_client_sign(client_name);
        if (!verify)
        {
            send_reply(newFD, "invalid");
            continue;
        }
        // creates the directory that will store the tables
        create_database();
        // executes the decrypted query with homomorphic encrypted values
        query_result = execute_query(message_decoded, client_name);
        // encrypt with session key and move to client folder
        if(query_result.compare("SELECT") == 0 && false) encode_message(query_result, client_name);

        send_reply(newFD, "finished");
    }
    /*********************************** accept messages **********************************/
}

