#include <iostream>
#include "sqlite3.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "openssl/rand.h"
#include "sstream"
#include "iomanip"
#include "random"
//used for database to stay open for entire project
sqlite3* DB;

using namespace std;
class database{
protected:
    char static CreatePepper(){
        //creates pepper
        char pepper;
        unsigned char randomByte;
        //picks a random number
        RAND_bytes(&randomByte, 1);
        int isLower = randomByte % 2;
        if (isLower) {
            // Adjust the range of the byte for lowercase letters a-z
            pepper = (randomByte % 26) + 'a';
        } else {
            // Adjust the range of the byte for uppercase letters A-Z
            pepper = (randomByte % 26) + 'A';
        }
        return pepper;
    };
    void getRowID(long long& rowid,  string& username){

        //setup for sqlite command
        sqlite3_stmt* stmt = nullptr;
        //the sqlite commande in question
        string sql = "select ROWID from Users where Usernames = ?";
        //prepares de commande to replace the ? with proper value
        int rc = sqlite3_prepare_v2(DB,sql.c_str(),-2,&stmt, nullptr);
        if(rc != SQLITE_OK){
            cerr<< "preperation for insertation failed";
            cout << endl << sqlite3_errmsg(DB);
        }
        //binds the username to the commande
        rc = sqlite3_bind_text(stmt,1,username.c_str(),-1,SQLITE_TRANSIENT);
        if(rc != SQLITE_OK){
            cerr<< "binding for username failed";
            cout << endl << sqlite3_errmsg(DB);
        }
// sends the command to the database
        rc = sqlite3_step(stmt);
        //if command succeeded take the value
        if(rc == SQLITE_ROW){
            rowid = sqlite3_column_int64(stmt,0);
        }
        else{
            cerr << "Retrieving ROWID failed: " << sqlite3_errmsg(DB) << endl;
        }
        //finalizes command
        sqlite3_finalize(stmt);

    }
    void GetInfoFromDB(long long&rowid, string&password, string&salt){
        //prepares what needed for sqlite
        sqlite3_stmt * stmt = nullptr;
        string sql = "SELECT Passwords,Salt from Users where ROWID = ?";
        int rc = sqlite3_prepare_v2(DB,sql.c_str(),-1,&stmt,nullptr);
        if(rc != SQLITE_OK){
            cout << "preparation fo extraction failed" << sqlite3_errmsg(DB) << endl;
        }
        //binds the row id to commande
         rc = sqlite3_bind_int64(stmt,1,rowid);
        if(rc != SQLITE_OK){
            cerr<< "binding for extraction failed";
            cout << endl << sqlite3_errmsg(DB);
        }
        //send command
        rc = sqlite3_step(stmt);
        if(rc == SQLITE_ROW){
            //if sucessful extracts data needed
           const unsigned char* temp = sqlite3_column_text(stmt,0);

           password = reinterpret_cast<const char*> (temp);
            temp = sqlite3_column_text(stmt,1);
            salt = reinterpret_cast<const char*> (temp);

        }
        sqlite3_finalize(stmt);


    }
    void hashPassword(string &password){

        // Initialize OpenSSL digest context
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            // Handle error
            throw std::runtime_error("Failed to create EVP_MD_CTX");
        }

        // Initialize the digest operation with SHA-256
        if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
            // Handle error
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize EVP Digest");
        }

        // Provide the message to be digested
        if (1 != EVP_DigestUpdate(ctx, password.c_str(), password.length())) {
            // Handle error
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update EVP Digest");
        }

        // Finalize the digest and get the hash
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int lengthOfHash = 0;
        if (1 != EVP_DigestFinal_ex(ctx, hash, &lengthOfHash)) {
            // Handle error
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize EVP Digest");
        }

        // Convert the binary hash to a hexadecimal string
        stringstream ss;
        for (unsigned int i = 0; i < lengthOfHash; ++i) {
            ss << hex << setw(2) << setfill('0') << (int)hash[i];
        }

        // Replace the original string with its hash value
        password = ss.str();

        // Clean up
        EVP_MD_CTX_free(ctx);
    };
    string createSalt(){
        char salt[64]; // Increase size for null-terminator if you need a string

        for(int i = 0; i < 62; i++) {
            unsigned char randomByte;
            RAND_bytes(&randomByte, 1);
            // Determine character case
            int isLower = randomByte % 2;
            if (isLower) {
                // Adjust the range of the byte for lowercase letters a-z
                salt[i] = (randomByte % 26) + 'a';
            } else {
                // Adjust the range of the byte for uppercase letters A-Z
                salt[i] = (randomByte % 26) + 'A';
            }
        }


        // Null-terminate if you intend to use it as a C-string
        salt[63] = '\0';

        return salt;

    }
public:
    bool static Exists(const string& username){
        //preparse commande for sql
            sqlite3_stmt* stmt = nullptr;
            string sql = "SELECT COUNT(*) FROM  Users   WHERE   Usernames   = ?";
            int rc = sqlite3_prepare_v2(DB, sql.c_str(), -1, &stmt, nullptr);

            if (rc != SQLITE_OK) {
                cout << "SQL error: " << sqlite3_errmsg(DB) << std::endl;
                sqlite3_finalize(stmt); // Clean up
                return false;  // Handle error more appropriately in real scenarios
            }
//binds the username to the commande
            sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

            bool exists = false;

            //does commande
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                //if there is a value them it exists
                exists = sqlite3_column_int(stmt, 0) > 0;
            }
            // Clean up
            sqlite3_finalize(stmt);
            return exists;
        };
    bool  CreateUser(const string& username, const string& password, const string& salt){

        //prepares for sqlite command
        sqlite3_stmt* stmt = nullptr;
        std::string sql = "insert into Users(Usernames, Passwords, Salt) VALUES (?, ?,?)";
        int rc = sqlite3_prepare_v2(DB,sql.c_str(),-1,&stmt,nullptr);
        if(rc != SQLITE_OK){
            cerr<< "preperation for insertation failed";
            cout << endl << sqlite3_errmsg(DB);
            return false;
        }
        //replaces the question mark with wanted value
        rc = sqlite3_bind_text(stmt,1,username.c_str(),-1,SQLITE_TRANSIENT);
        if(rc != SQLITE_OK){
            cerr<< "binding for username failed";
            cout << endl << sqlite3_errmsg(DB);
            return false;
        }
        rc = sqlite3_bind_text(stmt,2,password.c_str(),-1,SQLITE_TRANSIENT);
        if(rc != SQLITE_OK){
            cerr<< "binding for password  failed";
            cout << endl << sqlite3_errmsg(DB);
            return false;
        }
        rc = sqlite3_bind_text(stmt,3,salt.c_str(),-1,SQLITE_TRANSIENT);
        if(rc != SQLITE_OK){
            cerr<< "binding for salt  failed";
            cout << endl << sqlite3_errmsg(DB);
            return false;
        }
        //processes command
        rc=sqlite3_step(stmt);
        if(rc != SQLITE_DONE){
            cout << endl << sqlite3_errmsg(DB);
            return false;
        }
        //finalizes
        sqlite3_finalize(stmt);
        return true;


    };
};
class createUser : public database{
public:
    string password,Repassword,username;
    void askForDetails(){
        do{
            //asks for a username till you input one that is valid
                cout << "enter Username : ";
                cin >> username;
                bool taken = Exists(username);
                if(taken){
                    cout << "username Taken please try another" << endl;
                }

        }while(Exists(username));
        do{
            //enter your password till both passwords match
        cout << "enter password : ";
        cin >> password;

        cout << "reenter password : ";
        cin >> Repassword;
        if (password != Repassword)
            cerr << "password dont match try again";
        } while (password != Repassword);
        //creates salt which needs to be known
        string salt = createSalt();
        //adds salt to password;
        password = password+salt;
        //creates pepper and adds to password
        password = password + CreatePepper();
        hashPassword(password);
//creates user and handles an says if there is an error
        if(!CreateUser(username,password,salt)){
            cerr<< "erreur creating user";
        }
        else
            cout << "user created";

    }
};

class Login: public database {
private:
    long long rowId = 0;
    string realHashedPassword;
    string salt;


    bool verifiePassword(){
        //intilise i for pepper check
        char i = 'A';

        //adds all the possible pepper checks if it matches
        for(i;i<91; i++){
            string temp = enteredPass + i;
            hashPassword(temp);
            if(realHashedPassword == temp){
                return true;
            }
        }
        i= 'a';

        for(i ;i<123; i++){
            string temp = enteredPass + i;
            hashPassword(temp);
            if(realHashedPassword == temp){
                return true;
            }
        }
        //if none matches then its the wrong password
        return false;





    }
public:
    string enteredPass;
    string Username;

    void Info() {

        do {
            //enter the username
            cout << "enter username: ";
            cin >> Username;
            cout << "enter Password: ";
            cin >> enteredPass;
            if (!Exists(Username)) {
                //if usernames doesnt exist it says username or password incorrect so that hackers dont know which is worng
                cout << "username or Password incorrect please try again" << endl;
                continue;

            }
            //gets the id of the row where the user name is located
            getRowID(rowId,Username);

            //gets needed info from Database
            GetInfoFromDB(rowId,realHashedPassword,salt);
            //add the known salt for specifique user to password then procedes to next step
            enteredPass = enteredPass +salt;
            //checks if passwords are correct
            if(!verifiePassword()){
                cout << "username or Password incorrect please try again" << endl;
                continue;
            }
        } while (!Exists(Username) || !verifiePassword());

        cout << "LOGGED IN"<< endl;


    };
};

    int main() {
        //creates string for choice

        string choice;

        //connects to database

        int exit = 0;
        exit = sqlite3_open("credentialsDB.db", &DB);

        if (exit) {
            std::cerr << "Error open DB " << sqlite3_errmsg(DB) << std::endl;
            return (-1);
        } else
            std::cout << "Opened Database Successfully!" << std::endl;

//ask what they want to do then transformes it to lowercase
        cout << "To Create a New User enter New. To login entre Login" << endl;
        cin >> choice;
        transform(choice.begin(), choice.end(), choice.begin(), ::tolower);

        if (choice == "new") {
            auto *newUser = new createUser;
            newUser->askForDetails();
            delete (newUser);
        } else if (choice == "login") {
            auto *loginUser = new Login;
            loginUser->Info();
            delete (loginUser);
        }
        //closes connection
        int rc = sqlite3_close(DB);

        if(rc != SQLITE_OK){
            cout << "error closing Database : " << sqlite3_errmsg(DB);
        }
        else{
            cout << endl<< "Connection closed Successefully";
        }
        return 0;

    }
