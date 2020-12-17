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
string create_query(int input_opt, vector<string> *val_to_encrypt, int *query_num);
void decode_values();
void encode_values(vector<string> values);
bool verify_documents();
void print_commands();
void decode_message();
void encode_message(string message, int val_flag);
string connect_to_server(string message);
string load_string(string path);
int hex_to_dec(Plaintext plain_hex);

/* Functions of Server */
bool verify_root_CA();
int verify_client_sign(string name);
string decode_query(string name);
void encode_message(string query_result, string name);
void decode_values_message(string name);

void create_database();
int check_exists_table(string name);
void create_clients_file(string name, string client_name);
void create_column(string name, string column);
int create_table(string message, string client_name);
vector<string> check_query_names(string message_decoded, string *tablename, string command,int *row_num, vector<string> *colnames_op, vector<int> *logic, vector<int> *operators);
string execute_query(string message_decoded, string client_name);
void send_reply(int newFD, string reply);
vector<string> get_files_names(string tablename, string colname);

void delete_line(int row_num, string tablename);
void insert_values(int n_value, string tablename, vector<string> colname);
void select_line(string tablename, int row_num);
void select(vector<string> comparation_columns, vector<string> select_columns, string tablename, vector<int> operation, vector<int> logic, int flag_comm);


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