#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
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

BOOL DoSave(HWND hwnd, LPCWSTR pszFile)
{
    FILE *fp = _wfopen(pszFile, L"w");
    if (!fp)
    {
        MessageBoxW(hwnd, L"Cannot open file", NULL, MB_ICONERROR);
        return FALSE;
    }

    INT i, nCount = (INT)SendDlgItemMessageA(hwnd, lst1, LB_GETCOUNT, 0, 0);
    CHAR szText[512];

    for (i = 0; i < nCount; ++i)
    {
        SendDlgItemMessageA(hwnd, lst1, LB_GETTEXT, i, (LPARAM)szText);
        fprintf(fp, "%s\n", szText);
    }

    fclose(fp);
    return TRUE;
}

void OnSaveAs(HWND hwnd)
{
    WCHAR szFile[MAX_PATH] = L"";
    OPENFILENAMEW ofn = { OPENFILENAME_SIZE_VERSION_400W };
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Text File (*.txt)\0*.txt\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Save As";
    ofn.Flags = OFN_EXPLORER | OFN_ENABLESIZING | OFN_PATHMUSTEXIST |
                OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"txt";
    if (GetOpenFileNameW(&ofn))
    {
        DoSave(hwnd, szFile);
    }
}

void OnClear(HWND hwnd)
{
    SendDlgItemMessageA(hwnd, lst1, LB_RESETCONTENT, 0, 0);
}

void OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
    switch (id)
    {
    case IDOK:
    case IDCANCEL:
        EndDialog(hwnd, id);
        break;
    case psh1:
        OnSaveAs(hwnd);
        break;
    case psh2:
        OnClear(hwnd);
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
#ifndef HSHELL_FLASH
    #define HSHELL_FLASH (HSHELL_REDRAW | HSHELL_HIGHBIT)
#endif
#ifndef HSHELL_RUDEAPPACTIVATED
    #define HSHELL_RUDEAPPACTIVATED (HSHELL_WINDOWACTIVATED | HSHELL_HIGHBIT)
#endif

LRESULT OnShellHook(HWND hwnd, WPARAM wParam, LPARAM lParam)
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
    char buf[1024];
    if (IsWindow(hwndTarget))
    {
        char sz[64];
        GetClassNameA(hwndTarget, sz, 64);
        DWORD style = GetWindowStyle(hwndTarget);
        DWORD exstyle = GetWindowExStyle(hwndTarget);
        wsprintfA(buf, "%s: hwnd:%p ClassName:%s style:%08X exstyle:%08X",
            name, hwndTarget, sz, style, exstyle);
    }
    else
    {
        wsprintfA(buf, "%s: %p, %p", name, wParam, lParam);
    }
    {
        HDC hDC = GetDC(hwnd);
        SIZE siz;
        SelectObject(hDC, GetWindowFont(hwnd));
        GetTextExtentPoint32A(hDC, buf, lstrlenA(buf), &siz);
        ReleaseDC(hwnd, hDC);
        INT cx = SendDlgItemMessageA(hwnd, lst1, LB_GETHORIZONTALEXTENT, 0, 0);
        if (cx < siz.cx + 32)
            cx = siz.cx + 32;
        SendDlgItemMessageA(hwnd, lst1, LB_SETHORIZONTALEXTENT, cx, 0);
    }
    SendDlgItemMessageA(hwnd, lst1, LB_ADDSTRING, 0, (LPARAM)buf);

    return 0;
}

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
            return OnShellHook(hwnd, wParam, lParam);
        }
        break;
    }
    return 0;
}

INT WINAPI
WinMain(HINSTANCE   hInstance,
        HINSTANCE   hPrevInstance,
        LPSTR       lpCmdLine,
        INT         nCmdShow)
{
    InitCommonControls();
    DialogBox(hInstance, MAKEINTRESOURCE(1), NULL, DialogProc);
    return 0;
}
