#include <windows.h>
#include <string>
#include <iostream>

int main() {
    std::wstring progPath = L"C:\\Users\\jaken\\source\\repos\\Project2\\x64\\Release\\Project2.exe";
    HKEY hkey;
    LONG createStatus = RegCreateKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hkey);
    if (createStatus != ERROR_SUCCESS) {
        std::cout << "Failed to create registry key" << std::endl;
        return 1;
    }
    LONG status = RegSetValueEx(hkey, L"MyApp", 0, REG_SZ, (BYTE*)progPath.c_str(), (progPath.size() + 1) * sizeof(wchar_t));
    if (status != ERROR_SUCCESS) {
        std::cout << "Failed to set registry key value" << std::endl;
        return 1;
    }
    std::cout << "Registry key created and value set successfully" << std::endl;
    //end of creating registry key



    //start of payload
    STARTUPINFOA what;
    PROCESS_INFORMATION whatever;
    ZeroMemory(&what, sizeof(what));
    ZeroMemory(&whatever, sizeof(whatever));
    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &what, &whatever);


    //end of payload
    return 0;
}
