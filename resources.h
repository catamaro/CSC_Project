// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <memory>
#include <limits>
#include <algorithm>
#include <numeric>
#include "seal/seal.h"

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>  
#include <stdlib.h>
#include <sstream>
#include <chrono>
#include <ctime>    
#include <cstdio>
#include <stdexcept>
#include <array>

using namespace std;
using namespace seal;

/* Functions of logic comparator */
Ciphertext NOT (Ciphertext input, Evaluator* eval);
Ciphertext AND(Ciphertext inA, Ciphertext inB, Evaluator *eval);
Ciphertext OR(Ciphertext inA, Ciphertext inB, Evaluator *eval, RelinKeys relin_keys);
vector <Ciphertext> bit_Comparator (Ciphertext inA, Ciphertext inB, vector <Ciphertext> rolling, RelinKeys relin_keys, Evaluator* eval);
vector <Ciphertext> Full_comparator(vector <Ciphertext> A, vector <Ciphertext> B, RelinKeys relin_keys, Evaluator* eval);
vector<Ciphertext> encrypt_binaries(vector<int> binary, Encryptor *encriptor);
vector<int> dec_to_binary(int number);
vector<int> decrypt_binaries(vector<Ciphertext> results);

/* Functions of Client */
string create_query(vector<string> *val_to_encrypt, int *query_num);
void decode_values();
void encode_values(vector<string> values);
bool verify_documents();
void print_commands();
void decode_message(int flag_error);
void encode_message(string message, int val_flag);
string connect_to_server(string message);
string load_string(string path);
int hex_to_dec(Plaintext plain_hex);

/* Functions of Server */
bool verify_root_CA();
int verify_signatures(string name);
bool verify_certificates(string name);
string decode_query(string name);
void encode_message(string query_result, string name);
void decode_values_message(string name);
void encode_message_fail(string name);

void create_database();
int check_exists_table(string name);
void create_clients_file(string name, string client_name);
void create_column(string name, string column);
int create_table(string message, string client_name);
vector<string> check_query_names(string message_decoded, string *tablename, string command,int *row_num, vector<string> *colnames_op, vector<int> *logic, vector<int> *operators);
string execute_query(string message_decoded, string client_name);
void send_reply(int newFD, string reply);
vector<string> get_files_names(string tablename, string colname);
void delete_messages(string client_name);

int delete_line(int row_num, string tablename);
void insert_values(int n_value, string tablename, vector<string> colname, string client_name);
int select_line(string tablename, int row_num);
void select(vector<string> comparation_columns, vector<string> select_columns, string tablename, vector<int> operation, vector<int> logic, int flag_comm, string client_name);


std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

string load_string(string path)
{
    ifstream f(path);
    string str;
    if (f)
    {
        ostringstream ss;
        ss << f.rdbuf();
        str = ss.str();
    }
    f.close();

    return str;
}

tm get_time(){
    auto get_time = std::chrono::system_clock::now();

    std::time_t tt = std::chrono::system_clock::to_time_t(get_time);

    tm utc_tm = *gmtime(&tt);
    
    return utc_tm;
}

int get_month(string month_name){
    int month_num = -1;

    if(month_name.compare("Jan") == 0) month_num = 0;
    if(month_name.compare("Feb") == 0) month_num = 1;
    if(month_name.compare("Mar") == 0) month_num = 2;
    if(month_name.compare("Apr") == 0) month_num = 3;
    if(month_name.compare("May") == 0) month_num = 4;
    if(month_name.compare("Jun") == 0) month_num = 5;
    if(month_name.compare("Jul") == 0) month_num = 6;
    if(month_name.compare("Aug") == 0) month_num = 7;
    if(month_name.compare("Sep") == 0) month_num = 8;
    if(month_name.compare("Oct") == 0) month_num = 9;
    if(month_name.compare("Nov") == 0) month_num = 10;
    if(month_name.compare("Dec") == 0) month_num = 11;

    return month_num;
}

string verify_date(string exp_date, tm current_time){
    string delimiter = " ", token;
    vector<string> parsed_exp_date;
    int pos;

    while ((pos = exp_date.find(delimiter)) != string::npos){
        token = exp_date.substr(0, pos);
        exp_date.erase(0, pos + delimiter.length());
        parsed_exp_date.insert(parsed_exp_date.end(), token);
    }

    pos = parsed_exp_date.at(0).find("=");
    token = exp_date.substr(0, pos);
    parsed_exp_date.at(0).erase(0, pos + delimiter.length());

    int year = current_time.tm_year + 1900;
    if (stoi(parsed_exp_date.at(3)) == year){

        int month_num = get_month(parsed_exp_date.at(0));
        if (month_num == current_time.tm_mon){

            if (stoi(parsed_exp_date.at(1)) <= current_time.tm_mday){
                cout << "Certificate has expired! Message will not be considered" << endl;
                return "NOK";   
            }
        }
        else if (month_num < current_time.tm_mon){
            cout << "Certificate has expired! Message will not be considered" << endl;
            return "NOK";   
        }
    }
    else if (stoi(parsed_exp_date.at(3)) < year){
        cout << "Certificate has expired! Message will not be considered" << endl;
        return "NOK";   
    }
    return "OK";

}
