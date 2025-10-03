#include <bits/stdc++.h>
using namespace std;

void plusMinus(vector<int> arr) {
    int n = arr.size();
    int pos = 0, neg = 0, zero = 0;
    
    for (int x : arr) {
        if (x > 0) pos++;
        else if (x < 0) neg++;
        else zero++;
    }
    
    cout.setf(ios::fixed);
    cout << setprecision(6);
    cout << (double)pos / n << "\n";
    cout << (double)neg / n << "\n";
    cout << (double)zero / n << "\n";
}

int main() {
    int n;
    cin >> n;
    vector<int> arr(n);
    for (int i = 0; i < n; i++) {
        cin >> arr[i];
    }
    plusMinus(arr);
    return 0;
}
