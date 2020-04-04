#include <windows.h>
#include <windowsx.h>
#include <shlobj.h>
#include <stdio.h>

UINT uShellHookMsg = RegisterWindowMessageW(L"SHELLHOOK");

typedef BOOL (WINAPI *FN_RegisterShellHookWindow)(HWND);

FN_RegisterShellHookWindow pReg =
    (FN_RegisterShellHookWindow)GetProcAddress(GetModuleHandleA("user32"), "RegisterShellHookWindow");

BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
    pReg(hwnd);
    return TRUE;
}

void OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
    switch (id)
    {
    case IDOK:
    case IDCANCEL:
        EndDialog(hwnd, id);
        break;
    }
}

#define HSHELL_WINDOWCREATED 1
#define HSHELL_WINDOWDESTROYED 2
#define HSHELL_ACTIVATESHELLWINDOW 3
#define HSHELL_WINDOWACTIVATED 4
#define HSHELL_GETMINRECT 5
#define HSHELL_REDRAW 6
#define HSHELL_TASKMAN 7
#define HSHELL_LANGUAGE 8
#define HSHELL_SYSMENU  9
#define HSHELL_ENDTASK  10
#define HSHELL_ACCESSIBILITYSTATE 11
#define HSHELL_APPCOMMAND 12
#define HSHELL_WINDOWREPLACED 13
#define HSHELL_WINDOWREPLACING 14
#define HSHELL_MONITORCHANGED 16
#define HSHELL_HIGHBIT 0x8000
#define HSHELL_FLASH (HSHELL_REDRAW|HSHELL_HIGHBIT)
#define HSHELL_RUDEAPPACTIVATED (HSHELL_WINDOWACTIVATED|HSHELL_HIGHBIT)

INT_PTR CALLBACK
DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        HANDLE_MSG(hwnd, WM_INITDIALOG, OnInitDialog);
        HANDLE_MSG(hwnd, WM_COMMAND, OnCommand);
    default:
        if (uMsg == uShellHookMsg)
        {
            const char *name = "";
            switch (wParam)
            {
            case HSHELL_WINDOWCREATED: name = "HSHELL_WINDOWCREATED"; break;
            case HSHELL_WINDOWDESTROYED: name = "HSHELL_WINDOWDESTROYED"; break;
            case HSHELL_ACTIVATESHELLWINDOW: name = "HSHELL_ACTIVATESHELLWINDOW"; break;
            case HSHELL_WINDOWACTIVATED: name = "HSHELL_WINDOWACTIVATED"; break;
            case HSHELL_GETMINRECT: name = "HSHELL_GETMINRECT"; break;
            case HSHELL_REDRAW: name = "HSHELL_REDRAW"; break;
            case HSHELL_TASKMAN: name = "HSHELL_TASKMAN"; break;
            case HSHELL_LANGUAGE: name = "HSHELL_LANGUAGE"; break;
            case HSHELL_SYSMENU: name = "HSHELL_SYSMENU"; break;
            case HSHELL_ENDTASK: name = "HSHELL_ENDTASK"; break;
            case HSHELL_ACCESSIBILITYSTATE: name = "HSHELL_ACCESSIBILITYSTATE"; break;
            case HSHELL_APPCOMMAND: name = "HSHELL_APPCOMMAND"; break;
            case HSHELL_WINDOWREPLACED: name = "HSHELL_WINDOWREPLACED"; break;
            case HSHELL_WINDOWREPLACING: name = "HSHELL_WINDOWREPLACING"; break;
            case HSHELL_MONITORCHANGED: name = "HSHELL_MONITORCHANGED"; break;
            case HSHELL_FLASH: name = "HSHELL_FLASH"; break;
            case HSHELL_RUDEAPPACTIVATED: name = "HSHELL_RUDEAPPACTIVATED"; break;
            }
            HWND hwndTarget = (HWND)lParam;
            if (IsWindow(hwndTarget))
            {
                char sz[64];
                GetClassNameA(hwndTarget, sz, 64);
                DWORD style = GetWindowStyle(hwndTarget);
                DWORD exstyle = GetWindowExStyle(hwndTarget);
                printf("%s: %p, %p: hwnd:%p ClassName:%s style:%08X exstyle:%08X\n",
                    name, wParam, lParam, hwndTarget, sz, style, exstyle);
            }
            else
            {
                printf("%s: %p, %p\n", name, wParam, lParam);
            }
        }
        break;
    }
    return 0;
}

int main(void)
{
    DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(1), NULL, DialogProc);
    return 0;
}
