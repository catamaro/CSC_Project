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
            cout << "Certificate Validation: Verified OK" << endl;
        }
        else
        {
            root.close();
            cout << "CA inválido: não corresponde à root\n";
            return false;
        }
    }
    else return false;

    return true;
}

int verify_signatures(string name)
{
    bool validation;
    // extract client's public key from certificate
    string comm("openssl x509 -pubkey -noout -in Messages/");
    comm.append(name);
    comm.append("-cert.crt > Messages/");
    comm.append(name);
    comm.append("-publ.pem\n\n");

    const char *run_comm = comm.c_str();
    system(run_comm);

    // decode session key signature
    comm ="openssl enc -d -aes-256-cbc -pbkdf2 -in Messages/";
    comm.append(name);
    comm.append("-sign.sha256.enc -out Messages/");
    comm.append(name);
    comm.append("-sign.sha256 -pass file:./session.key");

    const char *run_comm2 = comm.c_str();
    system(run_comm2);

    // verify encrypted session key signature
    comm = "openssl dgst -sha256 -verify Messages/";
    comm.append(name);
    comm.append("-publ.pem -signature Messages/");
    comm.append(name);
    comm.append("-sign.sha256 session.key > Messages/verified.txt");

    const char *run_comm3 = comm.c_str();
    system(run_comm3);

    // load verified.txt to confirm signature
    string sign_check = load_string("Messages/verified.txt");

    system("rm Messages/verified.txt\n");

    if (sign_check.compare("Verified OK\n") == 0)
    {
        cout << "Signature Validation: " << sign_check << endl;
        validation = true;
    }
    else
    {
        cout << "\nerror: Signature not valid! Message will not be considered" << endl;
        validation = false;
    }

    // remove unecessary files - encrypted sesion key
    comm = "rm Messages/";
    comm.append(name);
    comm.append("-session.key.enc ");
    comm.append("Messages/");
    comm.append(name);
    comm.append("-sign.sha256 ");
    comm.append("Messages/");
    comm.append(name);
    comm.append("-cert.crt ");
    comm.append("Messages/");
    comm.append(name);
    comm.append("-publ.pem ");
    comm.append("Messages/");
    comm.append(name);
    comm.append("-sign.sha256.enc ");

    const char *run_comm4 = comm.c_str();
    system(run_comm4);

    // extract client's public key from certificate
    system("openssl x509 -pubkey -noout -in Files/root_ca.crt > Files/root_publ.key");

    // verify encrypted session key signature
    sign_check = exec("openssl dgst -sha256 -verify Files/root_publ.key -signature Files/DB_relin.sha256 Files/DB_relin.key");
    if (sign_check.compare("Verified OK\n") == 0) cout << "Relin DB Key Signature Validation: " << sign_check << endl;
    else{
        cout << "Signature not valid! Message will not be considered" << endl;
        validation = false;
    }


    return validation;
}
// function to verify files in client folder, certificates and keys
bool verify_certificates(string name)
{
    // check if client certificate is valid
    string comm("openssl verify -CAfile Files/root_ca.crt Messages/");
    comm.append(name);
    comm.append("-cert.crt > Messages/verified.txt");

    const char * run_comm = comm.c_str();
    system(run_comm);

    // load verified.txt to confirm signature
    string sign_check = load_string("Messages/verified.txt");
    system("rm Messages/verified.txt\n");

    string s_compare("Messages/");
    s_compare.append(name);
    s_compare.append("-cert.crt: OK");

    if (sign_check.find(s_compare) != 0)
    {
        cout << "Client certificate is not valid! Message will not be considered" << endl;
        return false;
    }

    // check if client certificate has expired
    comm = "openssl x509 -enddate -noout -in Messages/";
    comm.append(name);
    comm.append("-cert.crt");
    const char * run_comm1 = comm.c_str();

    string exp_date = exec(run_comm1);
    tm current_time = get_time();

    string check_date = verify_date(exp_date, current_time);
    if (check_date.compare("NOK") == 0) return false;


    // check if server certificate is valid
    sign_check = exec("openssl verify -CAfile Files/root_ca.crt Files/Server-cert.crt");
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

    // check if server's private key is coherent with server certificate
    string crt = exec("openssl x509 -noout -modulus -in Files/Server-cert.crt| openssl md5");
    string key = exec("openssl rsa -noout -modulus -in Files/Server-priv.pem | openssl md5");

    if (crt.compare(key))
    {
        cout << "Server's private key doesn't match with certificate" << endl;
        return false;
    }


    return true;
}

string decode_query(string *client_name)
{
    // take client name from first filename in the folder Messages
    string comm("cd Messages/");
    comm.append("\nls -1 | head -n 1");
    const char *run_comm = comm.c_str();
    string filename = exec(run_comm);

    if (!filename.empty())
        (*client_name) = filename.substr(0, 7);


    // decode session key
    comm = "openssl rsautl -decrypt -inkey Files/Server-priv.pem -in Messages/";
    comm.append(*client_name);
    comm.append("-session.key.enc -out session.key");
    const char *run_comm1 = comm.c_str();
    system(run_comm1);

    // descrypt message with session key
    comm ="openssl enc -d -aes-256-cbc -pbkdf2 -in Messages/";
    comm.append(*client_name);
    comm.append("-message.enc -out Messages/message.txt -pass file:./session.key");

    const char *run_comm2 = comm.c_str();
    system(run_comm2);

    // import message into variable
    string message_decoded = load_string("Messages/message.txt");

    comm = "rm Messages/message.txt Messages/";
    comm.append(*client_name);
    comm.append("-message.enc");

    const char *run_comm3 = comm.c_str();
    system(run_comm3);

    return message_decoded;
}

void encode_message_fail(string name){

    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Messages/fail.txt -out Messages/fail.enc -pass file:./session.key\n");

    string comm("mv Messages/fail.enc ../");
    comm.append(name);
    comm.append("/Answers");
    const char *run_comm = comm.c_str();
    system(run_comm);

    // remove unnecessary files: session key and plain-text message
    system("rm session.key Messages/fail.txt");
}

void encode_message(string query_result, string name)
{
    // encrypt query result with session key
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Messages/query_result.txt -out Messages/query_result.enc -pass file:./session.key\n");
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Messages/query_result_2.txt -out Messages/query_result_2.enc -pass file:./session.key\n");

    // moves encoded file to client answers folder
    string comm("mv Messages/query_result.enc Messages/query_result_2.enc ../");
    comm.append(name);
    comm.append("/Answers\n");

    const char *run_comm = comm.c_str();
    system(run_comm);

    // remove unnecessary files: session key and plain-text messages
    system("rm session.key Messages/query_result.txt Messages/query_result_2.txt");
}

void decode_values_message(string name)
{
    // descrypt message with session key
    string comm("openssl enc -d -aes-256-cbc -pbkdf2 -in Messages/");
    comm.append(name);
    comm.append("-values.enc -out Messages/");
    comm.append(name);
    comm.append("-values.txt -pass file:./session.key\n");

    const char *run_comm2 = comm.c_str();
    system(run_comm2);

    // remove unecessary files - encoded message with session key
    comm = "rm Messages/";
    comm.append(name);
    comm.append("-values.enc\n");

    const char *run_comm3 = comm.c_str();
    system(run_comm3);
}

/******************************************** SEAL functions ************************************************/

Ciphertext NOT (Ciphertext input, Evaluator* eval)
{
  int i=1;
  Ciphertext output;
  Plaintext i_plain(to_string(i));
  (*eval).negate_inplace(input);
  (*eval).add_plain(input, i_plain, output);
  //     Nº -> Simétrico -> +1
  // Caso A: 1 -> -1 -> 0
  // Caso B: 0 -> 0 -> 1


  return output;
}

Ciphertext AND(Ciphertext inA, Ciphertext inB, Evaluator *eval) /*Input is single bits - effectively a multiplication*/
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

vector <Ciphertext> bit_Comparator (Ciphertext inA, Ciphertext inB, vector <Ciphertext> rolling, RelinKeys relin_keys, Evaluator* eval)
{
  Ciphertext B_greater_A, A_greater_B, A_equal_B;


  B_greater_A = AND(NOT(inA, eval), inB, eval);
  (*eval).relinearize_inplace(B_greater_A, relin_keys);

  A_greater_B = AND(inA, NOT(inB, eval), eval);
  (*eval).relinearize_inplace(A_greater_B, relin_keys);

  A_equal_B = NOT(OR(A_greater_B, B_greater_A, eval, relin_keys), eval);

  if (rolling.empty()) /*First numbers*/
  {
      rolling.push_back(A_equal_B); //rolling[0]
      rolling.push_back(A_greater_B); //rolling[1]
      rolling.push_back(B_greater_A); //rolling[2]
  }
  else{
      rolling.at(0) = AND(A_equal_B, rolling.at(0), eval);
      (*eval).relinearize_inplace(rolling.at(0), relin_keys);
      rolling.at(1) = AND(OR(A_greater_B, rolling.at(1), eval, relin_keys), NOT(rolling.at(2), eval), eval);
      (*eval).relinearize_inplace(rolling.at(1), relin_keys);
      rolling.at(2) = AND(OR(B_greater_A, rolling.at(2), eval, relin_keys), NOT(rolling.at(1), eval), eval);
      (*eval).relinearize_inplace(rolling.at(2), relin_keys);
  }

  return rolling;
}

vector <Ciphertext> Full_comparator(vector <Ciphertext> A, vector <Ciphertext> B, RelinKeys relin_keys, Evaluator* eval)
{
 vector <Ciphertext> results;
 int size = A.size();
 int i;

 if (A.size() != B.size())
 {
   cout << "Erro - tamanhos diferentes\n";
   exit(1);
  }
  /*From MSB to LSB*/
 results = bit_Comparator(A.at(size-1), B.at(size-1), results, relin_keys, eval);
 for (i = size-2; i>=0; i--)
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
        cout << "Database created...\n";
    }
    else
    {
        cout << "Database already exists...\n";
    }
}

int check_exists_table(string name)
{

    string tbl("cd Encrypted_Database\n[ -d '");
    tbl.append(name);
    tbl.append("' ]");
    const char *table = tbl.c_str();
    if (system(table)) //Tabela não existe
    {
        /*string tbl("cd Encrypted_Database\n mkdir ");
        tbl.append(name);
        const char *table = tbl.c_str();
        system(table);*/
        return 1;
    }
    else
		return 0; //Tabela existe
}

int check_exists_colname(string colname, string tablename)
{

    string path("cd Encrypted_Database\n[ -d '");
    path.append(tablename);
    path.append("/");
    path.append(colname);
    path.append("' ]");
    const char *column = path.c_str();
    if (system(column)) /*Coluna não existe - Errado*/
    {
        cout << "Error - Column does not exist" << endl;

        return 1;
    }
    else //Coluna existe - OK
    {
        return 0;
    }
}

void create_clients_file(string name, string client_name)
{
    string filename(name);
    filename.append("_client.txt");

    //directory to create the file
    string path1("Encrypted_Database/");
    path1.append(name);
    path1.append("/");
    path1.append(filename);

    ofstream myfile(path1);

    string data("Client that own the table:");
    myfile << data;
    myfile << "\n";
    myfile << client_name;
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
}

int create_table(string message, string client_name)
{
    int table_exists;
    string word = "";
    string name = "";
    int i = 1;
    int j = 0;
    int get_col = 0;
    vector<string> colnames;
    string check_colname ="";
    int check_equal_columns = 0;
    int equal = 0;
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
        name = word;
    }
    //checking if there are columns with the same name
    for (int k = 0; k < colnames.size(); k++){
        for(int j = 0; j < colnames.size(); j++){
            if(colnames.at(k).compare(colnames.at(j)) == 0)
                equal++;
        }
        if (equal > 1){
            check_equal_columns = 1;
            cout << "Error: columns with the same name!" << endl;
            break;
        }
        else equal = 0;
    }

    if(check_equal_columns == 1) return 0; //equal colunms
    //remove \n
    if (!name.empty() && name[name.length() - 1] == '\n')
        name.erase(name.length() - 1);

    
    // Check if table already exists, if not, create; if yes, return error.
	table_exists = check_exists_table(name);

	if (table_exists == 1)
    {
      string tbl("cd Encrypted_Database\n mkdir ");
      tbl.append(name);
      const char *table = tbl.c_str();
      system(table);
    }
    else if (table_exists == 0)
    {
		cout << "Error: Table already exists" << endl;
		return 0;
    }
	//Creating name of the file that contains clients ID
    create_clients_file(name, client_name);

    //Creating columns
    for (int k = 0; k < colnames.size(); k++) create_column(name, colnames.at(k));

    return 1;
}

vector<string> check_query_names(string message_decoded, string *tablename, string command, int *row_num, vector<string> *colnames_op, vector<int> *logic, vector<int> *operators)
{
    vector<string> colnames = {};
    string s = message_decoded, delimiter = " ", token;
    int exists;

    size_t pos = 0, i = 1;
    while ((pos = s.find(delimiter)) != string::npos)
    {
        token = s.substr(0, pos);
        s.erase(0, pos + delimiter.length());

        if (i == 2 && command.compare("DELETE") == 0)
        {    //Linha não existe
            *row_num = stoi(token);
        }
        else if (i == 3 && command.compare("SELECT ROW") == 0)
        {
            *row_num = stoi(token);
        }
        else if (command.compare("INSERT") == 0)
        {
            if (i == 4)
            {
                exists = check_exists_table(token);
                if (exists == 1) //Table não existe
                {
					colnames.resize(0);
					return colnames;
                }
                *tablename = token;
            }
            else if (i == 5)
            {
                token.erase(0, 1);
                while (token.compare(")") != 0 && (pos = s.find(delimiter)) != string::npos)
                {
                    exists = check_exists_colname(token, *tablename);
                    if (exists == 1) //Colunas não existe
                    {
                      colnames.resize(0);
                      return colnames;
                    }
                    colnames.insert(colnames.end(), token);
                    token = s.substr(0, pos);
                    s.erase(0, pos + delimiter.length());
                }
            }
        }
        else if (command.compare("SELECT") == 0)
        {
            if (i == 2)
            {
                while (token.compare("FROM") != 0 && (pos = s.find(delimiter)) != string::npos)
                {
                    colnames.insert(colnames.end(), token);
                    token = s.substr(0, pos);
                    s.erase(0, pos + delimiter.length());
                }
            }
            else if (i == 3)
            {
                exists = check_exists_table(token);
                if (exists == 1) //Tabela não existe
                {
                  colnames.resize(0);
                  return colnames;
                }
                *tablename = token;

                for(int j = 0; j < colnames.size(); j++){
                    exists = check_exists_colname(colnames.at(j), *tablename);
                    if (exists == 1) //Colunas não existe
                    {
                      colnames.resize(0);
                      return colnames;
                    }
                }
            }
            else if (i == 5)
            {
                exists = check_exists_colname(token, *tablename);
                if (exists == 1) //Colunas não existe
                {
                  colnames.resize(0);
                  return colnames;
                }
                (*colnames_op).insert((*colnames_op).end(), token);
            }
            else if (i == 6)
            {
                if (token.compare("=") == 0)
                    (*operators).insert((*operators).end(), 0);
                else if (token.compare(">") == 0)
                    (*operators).insert((*operators).end(), 2);
                else if (token.compare("<") == 0)
                    (*operators).insert((*operators).end(), 1);
                else
                {
                  cout << "Erro: Insira um operador válido [>|<|=]";
                  colnames.resize(0);
                  return colnames;
                }
            }
            else if (i == 8)
            {
                //logic
                if (token.compare("AND") == 0)
                    (*logic).insert((*logic).end(), 0);
                else if (token.compare("OR") == 0)
                    (*logic).insert((*logic).end(), 1);
                else
                {
                    cout << "Erro: Insira um operador válido [AND ou OR]";
                    colnames.resize(0);
                    return colnames;
                }
                i = 4;
            }
        }
        else if (command.compare("SUM") == 0)
        {
            if (i == 2)
            {
                token.erase(0, 4);
                token.erase(token.length() - 1, 1);
                colnames.insert(colnames.begin(), token);
            }
            else if (i == 4)
            {
                exists = check_exists_table(token);
                if (exists == 1) //Table não existe
                {
                  colnames.resize(0);
                  return colnames;
                }
                *tablename = token;

                for(int j = 0; j < colnames.size(); j++){
                    exists = check_exists_colname(colnames.at(j), *tablename);
                    if (exists == 1) //Colunas não existe
                    {
                      colnames.resize(0);
                      return colnames;
                    }
                }
            }
            else if (i == 5)
            {
                i = 4;
                command = "SELECT";
            }
        }
        i++;
    }
    if (command.compare("DELETE") == 0 || command.compare("SELECT ROW") == 0)
        (*tablename) = s;

    (*tablename).erase(remove((*tablename).begin(), (*tablename).end(), '\n'), (*tablename).end());

    if (check_exists_table(*tablename) != 0)
    {
        cout << "Error: Table does not exist" << '\n';
        colnames.resize(0);
	    return colnames;
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
    int equal = 0;

    if (message_decoded.find("CREATE TABLE") == 0)
    {
		int table_exists;
		cout << "Executing Create Table..." << endl;
		table_exists = create_table(message_decoded, client_name);
        if (table_exists == 1)
            return "CREATE";
        else if (table_exists == 0)
			return "FAILURE";
	}
	else if (message_decoded.find("INSERT") == 0)
    {
        cout << "Executing Insert..." << endl;
        colnames = check_query_names(message_decoded, &tablename, "INSERT", &row_num, {}, {}, {});
        if (colnames.size() == 0)
            return "FAILURE";

        for (int k = 0; k < colnames.size(); k++){
            for(int j = 0; j < colnames.size(); j++){
                if(colnames.at(k).compare(colnames.at(j)) == 0)
                    equal++;
            }
            if (equal > 1){
                cout << "Error: columns with the same name!" << endl;
                return "FAILURE";
            }
            else equal = 0;
        }
        
        int n_values = count(message_decoded.begin(), message_decoded.end(), '%');

        string comm2("cd Encrypted_Database/");
		comm2.append(tablename);
		comm2.append("\nfind -maxdepth 1 -type d -print| wc -l");

		const char *run_comm2 = comm2.c_str();
        string check = exec(run_comm2);
        int n_cols = stoi(check);

        cout << "n_cols: " << n_cols << " n_values: " << n_values << endl;
        if (n_cols-1 != n_values){
            cout << "Erro - Não inseriu colunas suficientes" << endl;
            return "FAILURE";
        } 

        decode_values_message(client_name);

        insert_values(n_values, tablename, colnames, client_name);

        return "INSERT";
    }
    else if (message_decoded.find("DELETE") == 0)
    {
        cout << "Executing Delete..." << endl;
        int exists;
        vector<string> ret;

        ret = check_query_names(message_decoded, &tablename, "DELETE", &row_num, {}, {}, {});
        if (ret.size() == 0)
            return "FAILURE";

        exists = delete_line(row_num, tablename);

        if (exists == 1) return "FAILURE";
        else return "DELETE";
    }
    else if (message_decoded.find("SELECT ROW") == 0)
    {
        cout << "Executing Select Row..." << endl;

        vector<string> ret;
		int valid;

		ret = check_query_names(message_decoded, &tablename, "SELECT ROW", &row_num, {}, {}, {});
        if (ret.size() == 0)
            return "FAILURE";

        valid = select_line(tablename, row_num);
        if (valid == 1) //Todas as filas existem
            return "SELECT";
        else if (valid == 0)
			return "FAILURE";
	}
	else if (message_decoded.find("SELECT SUM") == 0)
    {
        cout << "Executing Select Sum..." << endl;

        colnames = check_query_names(message_decoded, &tablename, "SUM", &row_num, &colnames_op, &logic, &operators);
        if (colnames.size() == 0)
            return "FAILURE";

        decode_values_message(client_name);

        select(colnames_op, colnames, tablename, operators, logic, 1, client_name);

        return "SELECT";
    }
    else if (message_decoded.find("SELECT") == 0)
    {
        cout << "Executing Select..." << endl;

        colnames = check_query_names(message_decoded, &tablename, "SELECT", &row_num, &colnames_op, &logic, &operators); 
        if (colnames.size() == 0)
            return "FAILURE";

        for (int k = 0; k < colnames.size(); k++){
            for(int j = 0; j < colnames.size(); j++){
                if(colnames.at(k).compare(colnames.at(j)) == 0)
                    equal++;
            }
            if (equal > 1){
                cout << "Error: columns with the same name!" << endl;
                return "FAILURE";
            }
            else equal = 0;
        }

        decode_values_message(client_name);

        select(colnames_op, colnames, tablename, operators, logic, 0, client_name);

        return "SELECT";
    }
    else
    {
        cout << "Command not found!" << '\n';
    }

    return "FAILURE";
}

vector<string> get_files_names(string tablename, string colname)
{
    string path("Encrypted_Database/");
    path.append(tablename);
    path.append("/");

    string comm("cd ");
    comm.append(path);
    if (colname.compare(" ") != 0)
    {
        comm.append("\n for file in ");
        comm.append(colname);
        comm.append("/* ; do  echo \"$file\"; done");
    }
    else
        comm.append("\n for folder in */; do  echo \"$folder\"; done");

    const char *run_comm = comm.c_str();
    string result = exec(run_comm);

    vector<string> names = {};
    string delimiter = "\n", token;
    size_t pos = 0;
    // separate string result in various column names
    while ((pos = result.find(delimiter)) != std::string::npos)
    {
        token = result.substr(0, pos);
        result.erase(0, pos + delimiter.length());

        names.insert(names.end(), token);
    }
    return names;
}

void delete_messages(string client_name){
    
    string file_names = exec("for file in Messages/* ; do  echo \"$file\"; done");

    vector<string> names = {};
    string delimiter = "\n", token;
    size_t pos = 0;

    string check = exec("if    ls -1qA Messages/ | grep -q .; then  ! echo not empty; else  echo empty; fi");
    if (check.compare("empty\n") != 0){
        // separate string result in various column names
        while ((pos = file_names.find(delimiter)) != std::string::npos)
        {
            token = file_names.substr(0, pos);
            file_names.erase(0, pos + delimiter.length());
            names.insert(names.end(), token);
        }

        for(int i = 0; i < names.size(); i++){      
            if(names.at(i).find(client_name) != names.at(i).size()){
                string comm = "rm ";
                comm.append(names.at(i));
                const char *run_comm = comm.c_str();
                system(run_comm);
            } 
        }

    }
    
    string result = exec("if [ -f 'Messages/query_result.txt' ]; then     echo 'exists.'; fi");
    if (result.compare("exists\n") == 0) system("rm Messages/query_result.txt");

    ofstream failure_file("Messages/fail.txt");

    failure_file << "Query could not be computed";

    failure_file.close();
} 

/***************************************** Query Functions *********************************************/

void insert_values(int n_value, string tablename, vector<string> colname, string client_name)
{
    SEALContext context = create_context();
    vector<Ciphertext> value_encrypted(9);
	string table_path;
    ifstream values_file;

	string path_name("Messages/");
    path_name.append(client_name);
    path_name.append("-values.txt");
    values_file.open(path_name, ios::binary);

    string path("Encrypted_Database/");
    path.append(tablename);
	path.append("/");
	path.append(colname.at(0));

	string comm("cd ");
    comm.append(path);
    comm.append("\nls -1 | tail -n 1");

    const char *run_comm = comm.c_str();
    string last_row_name = exec(run_comm);

    int last_row;
    if (last_row_name.compare("") == 0)
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
    values_file.close();
    
    string comm2("rm Messages/");
    comm2.append(client_name);
    comm2.append("-values.txt");

    const char *run_comm2 = comm2.c_str();
    system(run_comm2);
}

int delete_line(int row_num, string tablename)
{
    bool all_exist = true;

    string path("Encrypted_Database/");
    path.append(tablename);
    path.append("/*/");
    path.append(to_string(row_num));
    path.append(".txt");

    string comm("rm ");
    string results;
    comm.append(path);

    const char *run_comm = comm.c_str();

    vector<string> colnames = get_files_names(tablename, " ");

    for(int i=0; i < colnames.size(); i++){
        string path2("Encrypted_Database/");
        path2.append(tablename);
        path2.append("/");
        path2.append(colnames.at(i));
        path2.append("/");
        path2.append(to_string(row_num));
        path2.append(".txt");

        string comm2 = "if [ -f '";
        comm2.append(path2);
        comm2.append("' ]; then     echo 'exists'; fi");
        const char *run_comm2 = comm2.c_str();
        results = exec(run_comm2);
        if (results.compare("exists\n") == 0) all_exist = true;
        else{
            cout << "Erro: Linha não existe" << endl;
            return 1; 
        }
    }

    system(run_comm);
    return 0;
}

int select_line(string tablename, int row_num)
{
    // get column names
    vector<string> col_names = get_files_names(tablename, " ");

    // get values into single file to be sent
    SEALContext context = create_context();
    Ciphertext value_encrypted;

    ofstream result_file;
    result_file.open("Messages/query_result.txt", ios::binary);

    for (int j = 0; j < col_names.size(); j++)
    {
        string value_path("Encrypted_Database/");
        value_path.append(tablename); //Não falta barras? - Não porque o nome das pastas já vêm com barra - Amaro
        value_path.append("/");
        value_path.append(col_names.at(j));
        value_path.append(to_string(row_num));
        value_path.append(".txt");

        ifstream entry_file;
        entry_file.open(value_path, ios::binary);

        if(!entry_file) //Ficheiro não existe
        {
			cout << "Erro - Linha não existe" << endl;
			return 0;
		}

		value_encrypted.load(context, entry_file);
        value_encrypted.save(result_file);

        entry_file.close();
    }
    result_file.close();

    ofstream infile("Messages/query_result_2.txt");
    // store number of values that is being sent in file
    infile << to_string(col_names.size()) << endl;
    // save column names to send to client
    for (int j = 0; j < col_names.size(); j++)
        infile << col_names.at(j) << endl;

    infile.close();

    return 1;
}

void select(vector<string> comparation_columns, vector<string> select_columns, string tablename, vector<int> operation, vector<int> logic, int flag_comm, string client_name)
{ //operation(i): 0 if =; 1 if >; 2 if <
    SEALContext context = create_context();
    Evaluator evaluator(context);

    ifstream relin_keys_file;
    RelinKeys relin_keys;

    relin_keys_file.open("Files/DB_relin.key", ios::binary);
    relin_keys.load(context, relin_keys_file);

    vector<Ciphertext> compare_results, client_input(8), table_value_bits(8), output_values = {};
    Ciphertext mult_result, table_value_full;
    string curr_colname, path;
    ifstream table_value_file, client_values_file;

    int number_of_rows = 0;
    vector<vector<Ciphertext>> Comparasions_matrix;
    vector<Ciphertext> aux_vector, rowsToCollect;
    Ciphertext sums;

    vector<string> row_names = {};

    string path_name("Messages/");
    path_name.append(client_name);
    path_name.append("-values.txt");
    client_values_file.open(path_name, ios::binary);

    //1 - Ir buscar comparações
    for (int i = 0; i < comparation_columns.size(); i++)
    {
        client_input.at(0).load(context, client_values_file); // Carregar nº completo - para ser overwritten
        for (int i = 0; i < 8; i++)                               //Bits encriptados apenas. Não necessita do nº completo
            client_input.at(i).load(context, client_values_file);

        //Select column name.
        curr_colname = comparation_columns.at(i);

        row_names = get_files_names(tablename, curr_colname);

        if (row_names.size() > number_of_rows)
            number_of_rows = row_names.size(); //Ver o número máximo de linhas.

        aux_vector = {};
        for (int j = 0; j < row_names.size(); j++)
        {
            //Get Table values
            path = ("Encrypted_Database/");
            path.append(tablename);
            path.append("/");
            path.append(row_names.at(j));

            table_value_file.open(path, ios::binary);

            table_value_full.load(context, table_value_file); // Primeiro valor completo - Update: Desnecessário. Overwrite?
            for (int k = 0; k < 8; k++)                           //Depois bit a bit
                table_value_bits.at(k).load(context, table_value_file);

            table_value_file.close();

            compare_results = Full_comparator(client_input, table_value_bits, relin_keys, &evaluator);

            aux_vector.push_back(compare_results.at(operation.at(i)));
        }
        Comparasions_matrix.push_back(aux_vector);
    }

    //2 - Verificar a validade de cada linha, consoante o valor lógico definido
    for (int i = 0; i < row_names.size(); i++)
    {
        Ciphertext tmp_rowcollect;

        if (logic.at(0) == 0){ // AND = 0
            tmp_rowcollect = AND(Comparasions_matrix.at(0).at(i), Comparasions_matrix.at(1).at(i), &evaluator);
            evaluator.relinearize_inplace(tmp_rowcollect, relin_keys);
        }
        else if (logic.at(0) == 1){ // OR = 1
            tmp_rowcollect = OR(Comparasions_matrix.at(0).at(i), Comparasions_matrix.at(1).at(i), &evaluator, relin_keys);
        }

        rowsToCollect.push_back(tmp_rowcollect); //Linha 0 inserida na posição 0, 1 em 1...
    }

    //3 - SELECT OU SELECT SUM
    for (int i = 0; i < select_columns.size(); i++){
        curr_colname = select_columns.at(i); //Abrir a coluna de onde se retirará valores
        row_names = get_files_names(tablename, curr_colname);

        for (int j = 0; j < row_names.size(); j++)
        {
            //Get Table values
            path = ("Encrypted_Database/");
            path.append(tablename);
            path.append("/");
            path.append(row_names.at(j));

            table_value_file.open(path, ios::binary);
            table_value_full.load(context, table_value_file);
            table_value_file.close();

            evaluator.multiply(rowsToCollect.at(j), table_value_full, mult_result);
            evaluator.relinearize_inplace(mult_result, relin_keys);

            if(j == 0){
                output_values.insert(output_values.end(), mult_result); //O 1º vai sempre para o vetor, independentemente de qual seja o modo
            }
            else{
                if(flag_comm == 1){ // SELECT SUM
                    evaluator.add(output_values.at(0), mult_result, output_values.at(0)); //Vai somando o vetor inplace.
                }
                if(flag_comm == 0){ // SELECT
                    output_values.insert(output_values.end(), mult_result);               //Vai acrescentando mais
                }
            }
        }
    }


    //4 - Escrever mult result para ficheiro
    ofstream result_file, result_file_2;

    result_file.open("Messages/query_result.txt", ios::binary);
    result_file_2.open("Messages/query_result_2.txt", ios::binary);

    // store number of values that is being sent in file
    result_file_2 << to_string(output_values.size()) << endl;

    int m = 0, n = 0;
    int ret_per_num = output_values.size() / select_columns.size();
    for (int i = 0; i < output_values.size(); i++)
    {
        output_values.at(i).save(result_file); // saving output value
        if (m == ret_per_num){
            m = 0;
            n ++;
        }
        if (flag_comm == 1) result_file_2 << "sum(" + select_columns.at(n) + ")" << endl;
        else result_file_2 << select_columns.at(n) << endl;
        m++;
    }

    result_file.close();
    result_file_2.close();

    string comm2("rm Messages/");
    comm2.append(client_name);
    comm2.append("-values.txt");

    const char *run_comm2 = comm2.c_str();
    system(run_comm2);
}

/********************************************* Server Main **************************************************/

int main(int argc, char *argv[])
{
    bool run = true;
    int input;
    string message_decoded, query_result;

    string client_name;

    while (run)
    {
        cout << "\nTo continue select 1 to exit select 0: ";
        cin >> input;
        while(cin.fail() || (input != 0 && input != 1)) {
            cout << "That option is not available.\n";
            cin.clear();
            cin.ignore(256,'\n');
            cout << "To continue select 1 to exit select 0: ";
            cin >> input;
        }
        if(input == 0) break;
        
        // check if there are new files on the folder
        cout << "\nWaiting for new messages..." << endl;
        while (run){
            string check = exec("if    ls -1qA Messages/ | grep -q .; then  ! echo not empty; else  echo empty; fi");
            if (check.compare("empty\n") != 0) break;
        }

        // verify if root certificate is valid
        cout << "Verifying root certificate..." << endl;
        bool verify = verify_root_CA();
        if (!verify){
            delete_messages(client_name);
            continue;
        }

        cout << "Decrypting message..." << endl;
        // decode message and session key and saves it in folder
        message_decoded = decode_query(&client_name); // query decoded

        cout << "Verifying stored certificates..." << endl;
        // verify if client's signature is valid
        verify =  verify_certificates(client_name);
        if (!verify){
            delete_messages(client_name);
            continue;
        } 

        cout << "Verifying stored signatures..." << endl;
        // verify if client's signature is valid
        verify = verify_signatures(client_name);
        if (!verify) continue;

        // creates the directory that will store the tables
        cout << "Creating Database..." << endl;
        create_database();

        // executes the decrypted query with homomorphic encrypted values
        query_result = execute_query(message_decoded, client_name);

        // encrypt with session key and move to client folder
        if (query_result.compare("SELECT") == 0){
            cout << "Encrypting and Sending query answer..." << endl;
            encode_message(query_result, client_name);
        }
        else if (query_result.compare("FAILURE") == 0){
            delete_messages(client_name);
            encode_message_fail(client_name);
        }
    }
    system("cd .. \n ./clear_files.sh");

    return EXIT_SUCCESS;
}
