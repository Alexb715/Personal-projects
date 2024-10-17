#include <iostream>
#include <map>
using namespace std;
int main() {
    string valid;
    getline(cin, valid);
    map<char, int> data;
    string words = "";
    while(getline(cin, words)) {
        for(auto i : words) {
            if(!isalpha(i)) {
                continue;
            }
            data[i]++;
        }
        string word="";
        for(auto i : data) {
            auto tmp = i.second;
            char tmp2 = i.first;
            word.append(to_string(tmp));
            word += tmp2;
        }
        if(valid == word) {
            cout << word << endl;
            return 0;
        }
        word.clear();
        words.clear();
        data.clear();
    }
}
